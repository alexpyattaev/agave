use std::time::Duration;

use iocraft::prelude::*;
#[derive(Debug, Props)]
pub struct BarProps<T>
where
    T: Into<f32>,
    T: Send + Default + Sync + Clone,
{
    pub max_val: T,
    pub val: T,
    pub units: &'static str,
    pub label: &'static str,
}
impl<T> Default for BarProps<T>
where
    T: From<u8>,
    T: Into<f32>,
    T: Send + Default + Sync + Clone,
{
    fn default() -> Self {
        Self {
            max_val: T::from(100),
            val: T::from(0),
            units: r"%",
            label: "",
        }
    }
}

#[component]
pub fn BarIndicator<T>(props: &BarProps<T>) -> impl Into<AnyElement<'static>>
where
    T: Into<f32>,
    T: Send + Default + Sync + Clone,
    T: 'static,
{
    let pos: f32 = props.val.clone().into();
    let max: f32 = props.max_val.clone().into();
    let color = if pos < max { Color::Green } else { Color::Red };
    element! {
        View {
            View(padding: 1) {
                            Text(content: format!("{}", props.label))
                        }
            View(border_style: BorderStyle::Round, border_color: Color::Blue, width: 60) {
                View(width: Percent(pos.min(max)/max*100.0), height: 1, background_color: color )
            }
            View(padding: 1) {
                Text(content: format!("{:.0}{}", pos, props.units))
            }
        }
    }
}

#[derive(Debug, Props)]
pub struct RateDisplayProps {
    pub rates: Vec<f32>,
    pub units: &'static str,
    pub label: &'static str,
}

#[component]
fn RateDisplay(mut hooks: Hooks, props: &RateDisplayProps) -> impl Into<AnyElement<'static>> {
    let rates = props.rates.clone();
    element! {
        View(border_style: BorderStyle::Round, border_color: Color::Cyan) {
            #(rates.iter().map(|r|{
            ui::BarIndicator<f32>(label:"Speed", max_val:1000.0, units:"Mbps",
                val:progress.get()
                }
            )

        }
    }
}
