use rand::{thread_rng, Rng};
use std::time::SystemTime;
#[macro_use]
use time::{PrimitiveDateTime, format_description};
use chrono::prelude::*;

pub fn now_datetime() -> Option<PrimitiveDateTime> {
    let now = Local::now();
    let now_datetime = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
    let format =
        format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap();
    let current_datetime = PrimitiveDateTime::parse(&now_datetime, &format);
    if current_datetime.is_err() {
        return None;
    } else {
        return Some(current_datetime.unwrap());
    }
}
