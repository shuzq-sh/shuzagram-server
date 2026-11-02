// Verify a gift sticker downloads via upload.getFile against a running server.
use gram_edge::client::Client;
use mtproto_crypto::rsa_key::ServerRsaKey;
use tl_core::{Reader, Writer};

fn wrap(q:&[u8])->Vec<u8>{let mut i=Writer::new();i.write_u32(0xc1cd_5ea9);i.write_i32(0);i.write_i32(12345);
 for s in ["Rust","Linux","1.0","en","","en"]{i.write_string(s);} i.write_raw(q);
 let mut w=Writer::new();w.write_u32(0xda9b_0d0d);w.write_i32(232);w.write_raw(&i.into_vec());w.into_vec()}

fn main(){
 let addr=std::env::var("ADDR").unwrap(); let key=std::env::var("SHUZA_RSA_KEY").unwrap();
 let gid:i64=std::env::var("GID").unwrap().parse().unwrap();
 let rsa=ServerRsaKey::load_or_generate(&key).unwrap();
 let mut c=Client::connect_and_handshake(&addr,&rsa).expect("hs");
 // upload.getFile(inputDocumentFileLocation{id,access_hash,file_ref,thumb}, offset, limit)
 let mut q=Writer::new();
 q.write_u32(0xbe53_35be); // upload.getFile
 q.write_i32(0); // flags
 q.write_u32(0xbad0_7284); // inputDocumentFileLocation
 q.write_i64(gid); q.write_i64(gid.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64));
 q.write_bytes(&[]); q.write_string("");
 q.write_i64(0); q.write_i32(1024*1024);
 let (_id,reply)=c.invoke(&wrap(&q.into_vec())).unwrap();
 // rpc_result -> upload.file#096a18d5 type mtime bytes
 let mut r=Reader::new(&reply);
 let ctor=r.read_u32().unwrap();
 if ctor==0xf35c_6d01 { let _=r.read_i64(); } // rpc_result req_msg_id
 let up=r.read_u32().unwrap(); // upload.file
 let _ty=r.read_u32().unwrap(); let _mt=r.read_i32().unwrap();
 let bytes=r.read_bytes().unwrap();
 println!("upload.file ctor={:#x} sticker bytes={} (gift {})", up, bytes.len(), gid);
}
