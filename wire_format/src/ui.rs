use std::sync::Arc;

use iocraft::prelude::*;
use tokio::sync::broadcast::Receiver;
#[derive(Default, Debug, Props)]
/*pub struct BarProps<T>
where
    T: Into<f32>,
    T: Send + Default + Sync + Clone,
{
    pub max_val: T,
    pub initial_val: T,
    //value_rx: Option<Receiver<T>>,
    pub label: &'static str,
}*/
pub struct BarProps {
    pub max_val: f32,
    pub initial_val: f32,
    //value_rx: Option<Receiver<T>>,
    pub label: &'static str,
}
/*pub struct BarPosition<T>(pub T)
where
    T: Into<f32>,
    T: Send + Default + Sync + Clone;*/
pub struct BarPosition(pub f32);

#[component]
//fn BarIndicator<T>(mut hooks: Hooks, props: &BarProps<T>) -> impl Into<AnyElement<'static>>
//pub fn BarIndicator<T>(props: &BarProps<T>) -> impl Into<AnyElement<'static>>
pub fn BarIndicator(mut hooks: Hooks, props: &BarProps) -> impl Into<AnyElement<'static>>
/*where
    T: Into<f32>,
    T: Send + Default + Sync + Clone,
    T: 'static,*/
{
    //let mut progress = hooks.use_state::<f32, _>(|| props.initial_val.clone().into());
    /*     hooks.use_future(async move {
        loop {
            progress.set(rx.recv().await.map(|v| v.into()).unwrap_or(0.0))
        }
    });*/
    //  let pos = hooks.use_context::<BarPosition<T>>();
    let pos = hooks.use_context::<BarPosition>();

    let max: f32 = props.max_val.clone().into();
    let color = if pos.0.clone() < max {
        Color::Green
    } else {
        Color::Red
    };
    element! {
        View {
            View(border_style: BorderStyle::Round, border_color: Color::Blue, width: 60) {
                View(width: Percent(pos.0.clone().min(max)/max*100.0), height: 1, background_color: color )
            }
            View(padding: 1) {
                Text(content: format!("{:.0}{}", pos.0.clone(), props.label))
            }
        }
    }
}
