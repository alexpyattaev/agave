use std::{collections::VecDeque, sync::atomic::Ordering, time::Duration};

use crossbeam_channel::TryRecvError;
use iocraft::prelude::*;

#[derive(Debug, Props)]
pub struct BarProps<T>
where
    T: Into<f64>,
    T: Send + Default + Sync + Clone,
{
    pub max_val: T,
    pub val: T,
    pub label_width: iocraft::Size,
    pub units: &'static str,
    pub label: String,
}
impl<T> Default for BarProps<T>
where
    T: From<u8>,
    T: Into<f64>,
    T: Send + Default + Sync + Clone,
{
    fn default() -> Self {
        Self {
            max_val: T::from(100),
            label_width: 0.into(),
            val: T::from(0),
            units: r"%",
            label: "".to_owned(),
        }
    }
}

#[component]
pub fn BarIndicator<T>(props: &BarProps<T>) -> impl Into<AnyElement<'static>>
where
    T: Into<f64>,
    T: Send + Default + Sync + Clone,
    T: 'static,
{
    let pos: f64 = props.val.clone().into();
    let max: f64 = props.max_val.clone().into();
    let color = if pos < max { Color::Green } else { Color::Red };
    element! {
        View {
            View(padding: 1, width:props.label_width) {
                            Text(content: format!("{}", props.label))
                        }
            View(border_style: BorderStyle::Round, border_color: Color::Blue, width: 60) {
                View(width: Percent((pos.min(max)/max*100.0) as f32), height: 1, background_color: color )
            }
            View(padding: 1) {
                Text(content: format!("{:.0} {}", pos, props.units))
            }
        }
    }
}

#[derive(Debug, Props)]
pub struct RateDisplayProps {
    pub rates: Vec<(String, f64)>,
    pub units: &'static str,
    pub max_val: f64,
}
impl Default for RateDisplayProps {
    fn default() -> Self {
        Self {
            rates: vec![],
            units: "Mbps",
            max_val: 1000.0,
        }
    }
}
#[component]
pub fn RateDisplay(props: &RateDisplayProps) -> impl Into<AnyElement<'static>> {
    let rates = props.rates.clone();
    let max_label_chars = rates.iter().map(|(l, _)| l.len()).max().unwrap_or(0) as u32;
    element! {
        View(border_style: BorderStyle::Round, border_color: Color::Cyan,
                        flex_direction: FlexDirection::Column
        )
        {
            #(rates.into_iter().enumerate().map(|(id,(n,r))|element!{
            BarIndicator<f64>(
                key: id,
                label_width: max_label_chars+2,
                label:n, max_val:props.max_val, units:props.units,
                                val:r
                            )
            }))

        }
    }
}

#[derive(Default, Props)]
pub struct FormFieldProps {
    pub label: String,
    pub value: Option<State<String>>,
    pub has_focus: bool,
}

#[component]
pub fn FormField(props: &FormFieldProps) -> impl Into<AnyElement<'static>> {
    let Some(mut value) = props.value else {
        panic!("value is required");
    };

    element! {
        View(
            border_style: if props.has_focus { BorderStyle::Round } else { BorderStyle::None },
            border_color: Color::Blue,
            padding_left: if props.has_focus { 0 } else { 1 },
            padding_right: if props.has_focus { 0 } else { 1 },
        ) {
            View(width: 15) {
                Text(content: format!("{}: ", props.label))
            }
            View(
                background_color: Color::DarkGrey,
                width: 30,
            ) {
                TextInput(
                    has_focus: props.has_focus,
                    value: value.to_string(),
                    on_change: move |new_value| {
                        value.set(new_value)},
                )
            }
        }
    }
}

#[derive(Default, Props)]
pub struct HlButtonProps {
    pub label: String,
    pub has_focus: bool,
    pub handler: Handler<'static, ()>,
}

#[component]
pub fn HlButton(props: &mut HlButtonProps, mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let color = if props.has_focus {
        Color::Blue
    } else {
        Color::DarkBlue
    };
    let mut has_focus = hooks.use_state(|| props.has_focus);
    if has_focus.get() != props.has_focus {
        has_focus.set(props.has_focus);
    }
    hooks.use_local_terminal_events({
        let mut handler = props.handler.take();
        move |event| match event {
            TerminalEvent::FullscreenMouse(FullscreenMouseEvent {
                kind: MouseEventKind::Down(_),
                ..
            }) => {
                handler(());
            }
            TerminalEvent::Key(KeyEvent { code, kind, .. })
                if has_focus.get()
                    && kind != KeyEventKind::Release
                    && (code == KeyCode::Enter || code == KeyCode::Char(' ')) =>
            {
                handler(());
            }
            _ => {}
        }
    });
    element! {
                View(border_style: BorderStyle::Round, border_color: color){
                    Text(content:&props.label)
                }
    }
}

#[component]
fn Menu(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let mut speeds =
        hooks.use_state::<Vec<(String, f64)>, _>(|| vec![("Speed".to_owned(), 0.0); 2]);
    hooks.use_future(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut speeds = speeds.write();
            for s in speeds.iter_mut() {
                s.1 += 1.0;
            }
        }
    });

    element! {
        View(border_style: BorderStyle::Round, border_color: Color::Cyan ) {
            RateDisplay(rates:speeds.read().clone(), )
        }
    }
}

#[component]
async fn MainMenu(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let mut system = hooks.use_context_mut::<SystemContext>();
    let mut focus = hooks.use_state(|| 0);
    let mut should_exit = hooks.use_state(|| false);
    hooks.use_terminal_events(move |event| match event {
        TerminalEvent::Key(KeyEvent { code, kind, .. }) if kind != KeyEventKind::Release => {
            match code {
                KeyCode::Esc => should_exit.set(true),
                //KeyCode::Enter => should_exit.set(true),
                KeyCode::Up => focus.set((focus - 1).max(0)),
                KeyCode::Down => focus.set((focus + 1).min(2)),
                _ => {}
            }
        }
        _ => {}
    });

    if should_exit.get() {
        system.exit();
    }
    // hooks.use_terminal_events(move |event| match event {
    //     TerminalEvent::Key(key_event) => {
    //         focus.set(focus + 1);
    //     }
    //     TerminalEvent::FullscreenMouse(fullscreen_mouse_event) => todo!(),
    //     TerminalEvent::Resize(_, _) => todo!(),
    //     _ => todo!(),
    // });
    element! {
        View(
            flex_direction: FlexDirection::Column,
            align_items: AlignItems::Center,
        )
        {
        Text(content: "BPF capture ready", color: Color::Grey, align: TextAlign::Center)
            //FormField(label: "Protocol", value: first_name, has_focus: focus == 1)
        HlButton( has_focus: focus == 0, handler:|_|{println!("Waa1");}, label:"Log traffic")
        HlButton( has_focus: focus == 1, handler:|_|{println!("Waa2");}, label:"Log bastards")
        HlButton( label:"test1", has_focus: focus == 2, handler:|_|{println!("waa3");})
        //FormField(label: "Last Name", value: last_name, has_focus: focus == 2)
        }
    }
}

pub type RateDisplayItems = Vec<(String, f64)>;
pub struct RatesMonitorChannel(pub crossbeam_channel::Receiver<RateDisplayItems>);

#[component]
pub fn RatesMonitorMenu(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let mut rates =
        hooks.use_state::<Vec<(String, f64)>, _>(|| vec![("Waiting for data".to_owned(), 0.0)]);
    let mut should_exit = hooks.use_state(|| false);
    let mut max_val = hooks.use_state(|| {
        let mut vv = VecDeque::<u32>::new();
        vv.push_back(1000);
        vv
    });

    let chan = hooks.use_context::<RatesMonitorChannel>().0.clone();
    hooks.use_future(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pkt = match chan.try_recv() {
                Ok(pkt) => pkt,
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => {
                    should_exit.set(true);
                    break;
                }
            };
            let maxval = pkt.iter().map(|(_, v)| *v as u32).max().unwrap_or(0);
            {
                let mut max_val = max_val.write();
                max_val.push_back(maxval);
                if max_val.len() > 5 {
                    max_val.pop_front();
                }
            }
            let mut rates_guard = rates.write();
            *rates_guard = pkt;
        }
    });
    if should_exit.get() || crate::EXIT.load(Ordering::Relaxed) {
        let mut system = hooks.use_context_mut::<SystemContext>();
        system.exit();
    }
    let smooth_max = match max_val.read().iter().max().cloned().unwrap() {
        0..=10 => 10,
        11..=100 => 100,
        101..=1000 => 1000,
        _ => 10000,
    };

    element! {
        RateDisplay(rates:rates.read().clone(), units:"Mbps", max_val:smooth_max as f64)
    }
}
