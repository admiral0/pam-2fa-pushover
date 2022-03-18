#[macro_use] extern crate pam;

use std::ffi::CStr;
use std::collections::HashMap;
use gethostname::gethostname;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};
use pam::conv::PamConv;
use pam::module::{PamHandle, PamHooks};
use pushover::API;
use pushover::requests::message::SendMessage;
use rand::Rng;

struct PamPushover;
pam_hooks!(PamPushover);

macro_rules! pam_try {
    ($e:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    );
    ($e:expr, $err:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {}", e);
                return $err;
            }
        }
    );
}

impl PamHooks for PamPushover {
    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let mut rng = rand::thread_rng();
        let otp = rng.gen::<u64>().to_string();
        let user = pam_try!(pamh.get_user(None));
        let hostname = gethostname();

        let args: Vec<_> = args.iter().map(|s| s.to_string_lossy().to_owned() ).collect();
        let args: HashMap<&str, &str> = args.iter().map(|s| {
            let mut parts = s.splitn(2, "=");
            (parts.next().unwrap(), parts.next().unwrap_or(""))
        }).collect();

        let token: &str = match args.get("token") {
            Some(url) => url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let user_token : &str = match args.get("user_token") {
            Some(url) => url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let title = format!("auth: {}", hostname.to_string_lossy());
        let message = format!("User {} has is attempting to login. OTP: {}", user, otp);

        let api = API::new();
        let mut msg = SendMessage::new(token, user_token, message);
        msg.set_title(title);

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };
        match api.send(&msg) {
            Result::Ok(_) => "",
            Result::Err(_) => return PamResultCode::PAM_AUTH_ERR
        };
        let password = pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, "Insert OTP: "));

        return match password {
            Some(p) => if p == otp {
                PamResultCode::PAM_SUCCESS
            } else {
                PamResultCode::PAM_AUTH_ERR
            }
            None => PamResultCode::PAM_AUTH_ERR
        }
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}