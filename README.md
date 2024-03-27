# AES 256 GCM with Enhancement

Inspired by simplicity of (let's say JWT) this crate provide high-level
abstraction for AES-GCM Crate with some enhancement such as expiration check

> **notes** : if you want to use os environment for "SINGLE" key management,
> you can use `AES_GCM_SECRET` env key

`WARNING : IN PRODUCTION DO NOT LEAVE SECRET EMPTY, AVOID AT ANY COSTS`

`WARNING : THIS CRATE DOES NOT IMPLEMENT "SIV"`

Content:
- Allowed Encrypted Data
- Returned Data
- Initialization
- Options
- Decrypting
- Error Coverage
- Usage Recommendation

---

#### Allowed data consumption

any data that can implement serde::Serialize

#### Returned data

any data that can implement serde::Deserialize


---
#### Initialization :: Using OS ENV
```rust
use aes_256_gcm::Client;

fn main(){
    // this will consume AES_GCM_SECRET
    // if no env found it would set to default empty
    let aes_client = Client::new(None);
}
```

#### Initialization :: Using Custom Secret
```rust
use aes_256_gcm::Client;

fn main(){
    let my_secret:&str = "some of my secret";
    let aes_client = Client::new(my_secret);
}
```

#### Options :: Normal without expiration
```rust
let result: Result<String, AesError> = client.encrypt(
    "something or struct", None
);
```

#### Options :: With Expiration "Second"
```rust
let result: Result<String, AesError> = client.encrypt(
    "something or struct",
    AesOptions::with_expire_second(3)
        .build()
);
```

#### Options :: With Expiration "chrono Date"
```rust
// let's just pretend this few days ahead
let date_expired = chrono::Utc::now();
// use it with 'with_expire_date'
let result: Result<String, AesError> = client.encrypt(
    "something or struct",
    AesOptions::with_expire_date(date_expired)
        .build()
);
```

#### Decrypting

`YourDataType` can be `String` or `struct` or anything,\
make sure it is the same data type with encryption, \
otherwise it wont decrypting.

> side notes : don't forget to check their expiration :D

```rust

let result: Result<YourDataType, AesError> = client.decrypt::<YourDataType>(&token);

```

#### Usage Recommendation

for usage it's better to know well about `Arc` or around `Mutex`, 
and how data being shared across thread. If your application shared with multiple 
thread or async it's better to do best-practice of data sharing.

if you're integrating to some kind of framework, try to understand how their data sharing works.

> for other example please visit [example](https://github.com/zonblade/aes-256-gcm-rs/example)\
> i'm opening to anyone want to contribute either example or crate improvement.