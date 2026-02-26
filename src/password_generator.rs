use rand::Rng;
use std::marker::PhantomData;
use crate::types;
use types::Password;

mod sealed {
    pub trait Sealed {}
}

pub struct Empty;
pub struct Ready;

pub trait CharsetState: sealed::Sealed {}

impl sealed::Sealed for Empty {}
impl sealed::Sealed for Ready {}
impl CharsetState for Empty {}
impl CharsetState for Ready {}

pub struct PasswordGenerator<State: CharsetState, const MIN_LENGTH: usize = 8> {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    _state: PhantomData<State>,
}

impl<const N: usize> PasswordGenerator<Empty, N> {
    pub fn new() -> Self {
        Self {
            length: N,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            _state: PhantomData,
        }
    }
}

impl<S: CharsetState, const N: usize> PasswordGenerator<S, N> {
    pub fn length(mut self, len: usize) -> Self {
        assert!(len >= N, "Длина {len} < минимума {N}");
        self.length = len;
        self
    }

    fn into_ready(self) -> PasswordGenerator<Ready, N> {
        PasswordGenerator {
            length: self.length,
            lowercase: self.lowercase,
            uppercase: self.uppercase,
            digits: self.digits,
            symbols: self.symbols,
            _state: PhantomData,
        }
    }
    pub fn has_lowercase(mut self) -> PasswordGenerator<Ready, N> {
        self.lowercase = true;
        self.into_ready()
    }
    pub fn has_uppercase(mut self) -> PasswordGenerator<Ready, N> {
        self.uppercase = true;
        self.into_ready()
    }
    pub fn has_digits(mut self) -> PasswordGenerator<Ready, N> {
        self.digits = true;
        self.into_ready()
    }
    pub fn has_symbols(mut self) -> PasswordGenerator<Ready, N> {
        self.symbols = true;
        self.into_ready()
    }
}

impl<const N: usize> PasswordGenerator<Ready, N> {
    pub fn generate(&self) -> Password {
        let mut pool = Vec::new();
        if self.lowercase {
            pool.extend('a'..='z');
        }
        if self.uppercase {
            pool.extend('A'..='Z');
        }
        if self.digits {
            pool.extend('0'..='9');
        }
        if self.symbols {
            pool.extend("!@#$%^&*".chars());
        }

        assert!(!pool.is_empty());

        let mut rng = rand::rng();
        let value: String = (0..self.length)
            .map(|_| pool[rng.random_range(0..pool.len())])
            .collect();

        Password::new(value)
    }
}

fn secure() -> PasswordGenerator<Ready, 20> {
    PasswordGenerator::<Empty, 20>::new()
        .has_lowercase()
        .has_uppercase()
        .has_digits()
        .has_symbols()
}

pub fn demo() {
    let password = PasswordGenerator::<Empty, 8>::new()
        .has_lowercase()
        .has_uppercase()
        .has_digits()
        .has_symbols()
        .length(8)
        .generate();

    fn save_credentials(username: &str, password: &Password) -> String {
        format!("Saving: user={}, password={}", username, password.as_str())
    }

    let result = save_credentials("Sergey", &password);
    println!("{result}");

    let secure_password = secure().generate();
    let secure_result = save_credentials("Sergey", &secure_password);
    println!("{secure_result}");
}
