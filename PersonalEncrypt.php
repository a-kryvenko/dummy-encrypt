<?php

class PersonalEncrypt
{
    /**
     * Multiplicity of allowed hash symbols
     */
    private const HASH_SYMBOLS = [
        'Q', 'C', 'W', '6', 'D', '7', '0', 'x', 'X', 'g', 'j', '3', 'G', 'J', 'S', 'K', 'L', 'p', '1', 'b', 'M', 'A', 'H', 'O', 'R', 'U', 'q', 'Y', '5', 'V', 'l', 'w', 'n', 'v', 'B', 't', '9', 'k', 'e', 'd', 'E', 'N', 'I', 'c', '2', 'r', 'y', 'h', 'z', 'f', 'F', 'i', 'u', '8', 'o', 'P', 'Z', 'T', 'm', 's', '4', 'a'
    ];

    /**
     * @var array<string, int>
     * Flipped multiplicity
     */
    private static array $hashSymbolsFlipped = [];

    /**
     * Size of hash symbols multiplicity
     */
    private const MULTIPLICITY_SIZE = 62;

    /**
     * Length of hashed string
     */
    private const HASH_LENGTH = 10;

    /**
     * Service parameter. Used to rift each symbol
     */
    private const RIFT_START = 213;

    private const MAX_NUMBER = 2147483647;

    /**
     * Encrypt given number
     *
     * @param int $number
     * @param string $salt
     * @return string
     * @throws UnexpectedValueException
     * @throws OutOfRangeException
     */
    public static function encrypt(int $number, string $salt): string
    {
        if ($number < 1 || $number > self::MAX_NUMBER) {
            throw new OutOfRangeException("Number \"$number\" out of range (1 - " . self::MAX_NUMBER . ")");
        }

        if (empty($salt)) {
            throw new UnexpectedValueException("Salt can't be empty");
        }

        $salt = md5($salt);

        $numberString = self::convertNumberToString($number);

        $pass = str_split(str_pad('', strlen($numberString), $salt));
        $splitString = str_split($numberString);
        $rift = self::RIFT_START;
        foreach ($splitString as $k => $v) {
            $splitString[$k] = self::chr(self::ord($v) + self::ord($pass[$k]) + $rift);
            $rift ++;
        }
        return join('', $splitString);
    }

    /**
     * Decrypt given encrypted string into number
     * @param string $cipher
     * @param string $salt
     * @return int
     * @throws UnexpectedValueException
     */
    public static function decrypt(string $cipher, string $salt): int
    {
        if (empty($salt)) {
            throw new UnexpectedValueException("Salt can't be empty");
        }
        $salt = md5($salt);

        $pass = str_split(str_pad('', strlen($cipher), $salt));
        $splitString = str_split($cipher);
        $rift = self::RIFT_START;
        foreach ($splitString as $k => $v) {
            $splitString[$k] = self::chr(self::ord($v) - self::ord($pass[$k]) - $rift);
            $rift ++;
        }
        return intval(join('', $splitString));
    }

    private static function convertNumberToString(int $number): string
    {
        $numberString = (string)$number;
        $len = strlen($numberString);
        if ($len < self::HASH_LENGTH) {
            for ($i = 0; $i < (self::HASH_LENGTH - $len); $i ++) {
                $numberString = '0' . $numberString;
            }
        }

        return $numberString;
    }

    /**
     * Return symbol number
     * @param string $symbol
     * @return int
     */
    private static function ord(string $symbol): int
    {
        $flipped = self::getFlippedHashSymbols();

        if (isset($flipped[$symbol])) {
            return $flipped[$symbol];
        }

        return 0;
    }

    /**
     * Return symbol by his number
     * @param int $number
     * @return string
     */
    private static function chr(int $number): string
    {
        $number = self::normalizeNumber($number);

        if (isset(self::HASH_SYMBOLS[$number])) {
            return self::HASH_SYMBOLS[$number];
        }

        return '0';
    }

    private static function normalizeNumber(int $number): int
    {
        while ($number >= self::MULTIPLICITY_SIZE) {
            $number = $number - self::MULTIPLICITY_SIZE;
        }
        while ($number < 0) {
            $number = $number + self::MULTIPLICITY_SIZE;
        }

        return $number;
    }

    private static function getFlippedHashSymbols(): array
    {
        if (empty(self::$hashSymbolsFlipped)) {
            self::$hashSymbolsFlipped = array_flip(self::HASH_SYMBOLS);
        }

        return self::$hashSymbolsFlipped;
    }
}
