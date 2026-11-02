use gram_edge::client::Client;
use mtproto_crypto::rsa_key::ServerRsaKey;
use tl_core::{Reader, Writer};

fn wrap(q: &[u8]) -> Vec<u8> {
    let mut i = Writer::new();
    i.write_u32(0xc1cd_5ea9);
    i.write_i32(0);
    i.write_i32(12345);
    for s in ["Rust", "Linux", "1.0", "en", "", "en"] {
        i.write_string(s);
    }
    i.write_raw(q);
    let mut w = Writer::new();
    w.write_u32(0xda9b_0d0d);
    w.write_i32(232);
    w.write_raw(&i.into_vec());
    w.into_vec()
}

fn rd_doc(r: &mut Reader) -> Result<(String, i64), String> {
    let c = r.read_u32().map_err(|e| format!("doc ctor {e:?}"))?;
    if c == 0x36f8_c871 {
        let _ = r.read_i64();
        return Ok(("(empty)".into(), 0));
    } // documentEmpty
    if c != 0x8fd4_c4d8 {
        return Err(format!("doc ctor {c:#x}"));
    }
    let fl = r.read_i32().map_err(|e| format!("{e:?}"))?;
    r.read_i64().ok();
    r.read_i64().ok();
    r.read_bytes().ok();
    r.read_i32().ok();
    let mime = r.read_string().map_err(|e| format!("mime {e:?}"))?.to_string();
    let size = r.read_i64().map_err(|e| format!("size {e:?}"))?;
    if fl & 1 != 0 {
        let n = r.read_vector_header().map_err(|e| format!("thumbs {e:?}"))?;
        for _ in 0..n {
            let pc = r.read_u32().map_err(|e| format!("{e:?}"))?;
            if pc == 0xd821_4d41 {
                r.read_string().ok();
                r.read_bytes().ok();
            } else {
                return Err(format!("thumb ctor {pc:#x}"));
            }
        }
    }
    if fl & 2 != 0 {
        return Err("video_thumbs present".into());
    }
    r.read_i32().ok(); // dc
    let na = r.read_vector_header().map_err(|e| format!("attrs {e:?}"))?;
    for _ in 0..na {
        let a = r.read_u32().map_err(|e| format!("attr ctor {e:?}"))?;
        match a {
            0x6c37_c15c => {
                r.read_i32().ok();
                r.read_i32().ok();
            }
            0x6319_d612 => {
                let af = r.read_i32().map_err(|e| format!("{e:?}"))?;
                r.read_string().map_err(|e| format!("alt {e:?}"))?;
                let ss = r.read_u32().map_err(|e| format!("ss {e:?}"))?;
                if ss != 0xffb6_2b95 {
                    return Err(format!("stickerset ctor {ss:#x}"));
                }
                if af & 1 != 0 {
                    return Err("maskcoords".into());
                }
            }
            other => return Err(format!("unknown attr {other:#x}")),
        }
    }
    Ok((mime, size))
}

fn main() {
    let addr = std::env::var("ADDR").unwrap();
    let key = std::env::var("SHUZA_RSA_KEY").unwrap();
    let rsa = ServerRsaKey::load_or_generate(&key).unwrap();
    let mut c = Client::connect_and_handshake(&addr, &rsa).expect("hs");

    // 1. getStarGifts
    println!("--- checking payments.getStarGifts ---");
    let mut q = Writer::new();
    q.write_u32(0xc456_3590);
    q.write_i32(0); // getStarGifts hash=0
    let (_i, reply) = c.invoke(&wrap(&q.into_vec())).unwrap();
    let mut r = Reader::new(&reply);
    let ctor = r.read_u32().unwrap();
    if ctor == 0xf35c_6d01 {
        let _ = r.read_i64();
    }
    let res = r.read_u32().unwrap();
    println!("result ctor={:#x} (want 2ed82995)", res);
    if res == 0x2144_ca19 {
        let code = r.read_i32().unwrap();
        let msg = r.read_string().unwrap();
        println!("RPC_ERROR {code} {msg}");
        return;
    }
    let _hash = r.read_i32().unwrap();
    let n = r.read_vector_header().unwrap();
    println!("gift vector count={}", n);
    for idx in 0..n {
        let g = r.read_u32().unwrap();
        if g != 0x313a_9547 {
            println!("gift[{idx}] BAD ctor {g:#x}");
            return;
        }
        let fl = r.read_i32().unwrap();
        let _id = r.read_i64().unwrap();
        match rd_doc(&mut r) {
            Ok((m, s)) => {
                if idx < 2 {
                    println!("gift[{idx}] flags={fl:#x} doc mime={m} size={s}");
                }
            }
            Err(e) => {
                println!("gift[{idx}] DOC PARSE FAIL: {e}");
                return;
            }
        }
        let _stars = r.read_i64().unwrap();
        if fl & 1 != 0 {
            r.read_i32().ok();
            r.read_i32().ok();
        }
        if fl & 16 != 0 {
            r.read_i64().ok();
        }
        let _conv = r.read_i64().unwrap();
        if fl & 2 != 0 {
            r.read_i32().ok();
            r.read_i32().ok();
        }
        if fl & 8 != 0 {
            r.read_i64().ok();
        }
        if fl & 16 != 0 {
            r.read_i64().ok();
        }
        if fl & 32 != 0 {
            r.read_string().ok();
        }
    }
    let _c = r.read_vector_header().unwrap(); // chats
    let _u = r.read_vector_header().unwrap(); // users
    println!("PARSED OK, remaining bytes = {}", r.remaining());
    assert_eq!(r.remaining(), 0, "getStarGifts has leftover bytes");

    // 2. help.getAppConfig gating flags
    println!("--- checking help.getAppConfig ---");
    let mut q = Writer::new();
    q.write_u32(0x61e3_f854); // help.getAppConfig
    q.write_i32(0); // hash
    let (_i, reply) = c.invoke(&wrap(&q.into_vec())).unwrap();
    println!("help.getAppConfig reply len={}, hex={:02x?}", reply.len(), &reply[..reply.len().min(32)]);
    let mut r = Reader::new(&reply);
    let ctor = r.read_u32().unwrap();
    println!("outer ctor={:#x}", ctor);
    if ctor == 0xf35c_6d01 {
        let _ = r.read_i64();
    }
    let res = r.read_u32().unwrap();
    assert_eq!(res, 0xdd18_782e, "want help.appConfig#dd18782e, got {res:#x}");
    let _hash = r.read_i32().unwrap();
    assert_eq!(r.read_u32().unwrap(), 0x99c1_d49d); // jsonObject
    let vlen = r.read_vector_header().unwrap();
    let mut kv = std::collections::HashMap::new();
    for _ in 0..vlen {
        assert_eq!(r.read_u32().unwrap(), 0xc0de_1bd9); // jsonObjectValue
        let k = r.read_string().unwrap().to_string();
        let val_ctor = r.read_u32().unwrap();
        match val_ctor {
            0xc734_5e6a => {
                let b = r.read_bool().unwrap();
                kv.insert(k, format!("bool:{b}"));
            }
            0x2be0_dfa4 => {
                let n = r.read_f64().unwrap();
                kv.insert(k, format!("num:{n}"));
            }
            0xb71e_767a => {
                let s = r.read_string().unwrap();
                kv.insert(k, format!("str:{s}"));
            }
            other => panic!("unexpected json value ctor {other:#x}"),
        }
    }
    assert_eq!(r.remaining(), 0, "appConfig response has leftover bytes");
    println!("appConfig keys: {:?}", kv);
    assert_eq!(
        kv.get("stargifts_blocked").map(|s| s.as_str()),
        Some("bool:false"),
        "stargifts_blocked MUST be false!"
    );
    assert_eq!(
        kv.get("stars_purchase_blocked").map(|s| s.as_str()),
        Some("bool:false"),
        "stars_purchase_blocked MUST be false!"
    );
    assert_eq!(
        kv.get("premium_purchase_blocked").map(|s| s.as_str()),
        Some("bool:false"),
        "premium_purchase_blocked MUST be false!"
    );
    assert_eq!(
        kv.get("stars_gifts_enabled").map(|s| s.as_str()),
        Some("bool:true")
    );
    println!("appConfig gating checks PASSED!");

    // 3. payments.getStarGiftCollections
    println!("--- checking payments.getStarGiftCollections ---");
    let mut q = Writer::new();
    q.write_u32(0x981b_91dd); // payments.getStarGiftCollections
    q.write_u32(0xf772_e685); // inputPeerSelf
    q.write_i64(0); // hash = 0
    let (_i, reply) = c.invoke(&wrap(&q.into_vec())).unwrap();
    let mut r = Reader::new(&reply);
    let ctor = r.read_u32().unwrap();
    if ctor == 0xf35c_6d01 {
        let _ = r.read_i64();
    }
    let res = r.read_u32().unwrap();
    assert_eq!(
        res, 0x8a29_32f3,
        "want payments.starGiftCollections#8a2932f3, got {res:#x}"
    );
    let collections_count = r.read_vector_header().unwrap();
    assert_eq!(collections_count, 0);
    assert_eq!(
        r.remaining(),
        0,
        "payments.starGiftCollections must have 0 leftover bytes"
    );

    let mut q = Writer::new();
    q.write_u32(0x981b_91dd); // payments.getStarGiftCollections
    q.write_u32(0xf772_e685); // inputPeerSelf
    q.write_i64(999); // hash != 0
    let (_i, reply) = c.invoke(&wrap(&q.into_vec())).unwrap();
    let mut r = Reader::new(&reply);
    let ctor = r.read_u32().unwrap();
    if ctor == 0xf35c_6d01 {
        let _ = r.read_i64();
    }
    let res = r.read_u32().unwrap();
    assert_eq!(
        res, 0xa0ba_4f17,
        "want payments.starGiftCollectionsNotModified#a0ba4f17, got {res:#x}"
    );
    assert_eq!(r.remaining(), 0);
    println!("payments.getStarGiftCollections checks PASSED!");
}
