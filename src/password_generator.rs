use crate::types;
use rand::RngExt;
use std::marker::PhantomData;
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

impl<const N: usize> Default for PasswordGenerator<Empty, N> {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn from_flags(
        length: usize,
        lowercase: bool,
        uppercase: bool,
        digits: bool,
        symbols: bool,
    ) -> PasswordGenerator<Ready, N> {
        assert!(
            lowercase || uppercase || digits || symbols,
            "At least one character set must be enabled"
        );
        assert!(length >= N, "Длина {length} < минимума {N}");
        PasswordGenerator {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
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

pub fn secure() -> PasswordGenerator<Ready, 20> {
    PasswordGenerator::<Empty, 20>::new()
        .has_lowercase()
        .has_uppercase()
        .has_digits()
        .has_symbols()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════
    // new() — дефолтные значения
    // ════════════════════════════════════════════

    #[test]
    fn new_sets_length_to_min() {
        let pg = PasswordGenerator::<Empty, 8>::new();
        assert_eq!(pg.length, 8);
        assert!(!pg.lowercase);
        assert!(!pg.uppercase);
        assert!(!pg.digits);
        assert!(!pg.symbols);
    }

    #[test]
    fn new_custom_min_length() {
        let pg = PasswordGenerator::<Empty, 20>::new();
        assert_eq!(pg.length, 20);
    }

    // ════════════════════════════════════════════
    // from_flags() — конструктор из рантайм флагов
    // ════════════════════════════════════════════

    #[test]
    fn from_flags_valid() {
        let pg = PasswordGenerator::<Empty, 8>::from_flags(16, true, false, true, false);
        assert_eq!(pg.length, 16);
        assert!(pg.lowercase);
        assert!(!pg.uppercase);
        assert!(pg.digits);
        assert!(!pg.symbols);
    }

    #[test]
    fn from_flags_all_charsets() {
        let pg = PasswordGenerator::<Empty, 8>::from_flags(10, true, true, true, true);
        assert!(pg.lowercase && pg.uppercase && pg.digits && pg.symbols);
    }

    #[test]
    #[should_panic(expected = "At least one character set must be enabled")]
    fn from_flags_no_charset_panics() {
        PasswordGenerator::<Empty, 8>::from_flags(16, false, false, false, false);
    }

    #[test]
    #[should_panic(expected = "< минимума")]
    fn from_flags_length_below_min_panics() {
        PasswordGenerator::<Empty, 8>::from_flags(4, true, true, true, true);
    }

    // ════════════════════════════════════════════
    // length() — сеттер длины
    // ════════════════════════════════════════════

    #[test]
    fn length_sets_value() {
        let pg = PasswordGenerator::<Empty, 8>::new().length(32);
        assert_eq!(pg.length, 32);
    }

    #[test]
    #[should_panic(expected = "< минимума")]
    fn length_below_min_panics() {
        PasswordGenerator::<Empty, 8>::new().length(3);
    }

    // ════════════════════════════════════════════
    // Builder chain: has_*() → Ready
    // ════════════════════════════════════════════

    #[test]
    fn has_lowercase_transitions_to_ready() {
        let pg = PasswordGenerator::<Empty, 8>::new().has_lowercase();
        // Если скомпилировалось — тип уже Ready. Проверяем флаг:
        assert!(pg.lowercase);
        assert!(!pg.uppercase);
        // generate() доступен на Ready:
        let _pw = pg.generate();
    }

    #[test]
    fn has_uppercase_transitions_to_ready() {
        let pg = PasswordGenerator::<Empty, 8>::new().has_uppercase();
        assert!(pg.uppercase);
        let _pw = pg.generate();
    }

    #[test]
    fn has_digits_transitions_to_ready() {
        let pg = PasswordGenerator::<Empty, 8>::new().has_digits();
        assert!(pg.digits);
        let _pw = pg.generate();
    }

    #[test]
    fn has_symbols_transitions_to_ready() {
        let pg = PasswordGenerator::<Empty, 8>::new().has_symbols();
        assert!(pg.symbols);
        let _pw = pg.generate();
    }

    #[test]
    fn builder_chain_multiple_charsets() {
        let pg = PasswordGenerator::<Empty, 8>::new()
            .has_lowercase()
            .has_uppercase()
            .has_digits();
        assert!(pg.lowercase && pg.uppercase && pg.digits);
        assert!(!pg.symbols);
    }

    #[test]
    fn builder_chain_length_then_charset() {
        let pg = PasswordGenerator::<Empty, 8>::new()
            .length(24)
            .has_lowercase()
            .has_symbols();
        assert_eq!(pg.length, 24);
        assert!(pg.lowercase && pg.symbols);
    }

    // ════════════════════════════════════════════
    // generate() — корректность вывода
    // ════════════════════════════════════════════

    #[test]
    fn generate_correct_length() {
        let pw = PasswordGenerator::<Empty, 8>::from_flags(32, true, true, true, true).generate();
        assert_eq!(pw.as_str().len(), 32);
    }

    #[test]
    fn generate_min_length() {
        let pw = PasswordGenerator::<Empty, 8>::from_flags(8, true, false, false, false).generate();
        assert_eq!(pw.as_str().len(), 8);
    }

    #[test]
    fn generate_lowercase_only() {
        let pw =
            PasswordGenerator::<Empty, 8>::from_flags(100, true, false, false, false).generate();
        assert!(pw.as_str().chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn generate_uppercase_only() {
        let pw =
            PasswordGenerator::<Empty, 8>::from_flags(100, false, true, false, false).generate();
        assert!(pw.as_str().chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn generate_digits_only() {
        let pw =
            PasswordGenerator::<Empty, 8>::from_flags(100, false, false, true, false).generate();
        assert!(pw.as_str().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_symbols_only() {
        let symbols: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*'];
        let pw =
            PasswordGenerator::<Empty, 8>::from_flags(100, false, false, false, true).generate();
        assert!(pw.as_str().chars().all(|c| symbols.contains(&c)));
    }

    #[test]
    fn generate_uniqueness() {
        let pg = PasswordGenerator::<Empty, 8>::from_flags(32, true, true, true, true);
        let pw1 = pg.generate();
        let pw2 = pg.generate();
        // При 32 символах из ~70 вариантов вероятность коллизии ≈ 0
        assert_ne!(pw1.as_str(), pw2.as_str());
    }

    #[test]
    fn generate_all_charsets_contains_variety() {
        // Генерируем длинный пароль и проверяем наличие символов из каждого набора.
        // При длине 200 вероятность отсутствия любого набора ничтожна.
        let pw = PasswordGenerator::<Empty, 8>::from_flags(200, true, true, true, true).generate();
        let s = pw.as_str();
        assert!(s.chars().any(|c| c.is_ascii_lowercase()), "no lowercase");
        assert!(s.chars().any(|c| c.is_ascii_uppercase()), "no uppercase");
        assert!(s.chars().any(|c| c.is_ascii_digit()), "no digits");
        let symbols: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*'];
        assert!(s.chars().any(|c| symbols.contains(&c)), "no symbols");
    }

    // ════════════════════════════════════════════
    // secure() — пресет
    // ════════════════════════════════════════════

    #[test]
    fn secure_preset_length_20() {
        let pg = secure();
        assert_eq!(pg.length, 20);
        assert!(pg.lowercase && pg.uppercase && pg.digits && pg.symbols);
    }

    #[test]
    fn secure_generates_20_chars() {
        let pw = secure().generate();
        assert_eq!(pw.as_str().len(), 20);
    }
}
