// Command lab_2 is a non-interactive CLI for the Polybius square (coordinate
// and row-shift modes) and Gronsfeld ciphers from "Лабораторна робота 2".
// Cipher implementations live in internal/lab_2_algo; internal/lab_2 wires
// them into a CipherService (composition_root.go); UTF-8 file I/O is shared
// with lab_1 (internal/lab_1_ext). This file only parses flags and prints
// results.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	lab_1ext "4c-security-labs/internal/lab_1_ext"
	lab_2 "4c-security-labs/internal/lab_2"
	algo "4c-security-labs/internal/lab_2_algo"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("lab_2", flag.ContinueOnError)
	fs.Usage = func() { printUsage(fs) }

	algoNum := fs.Int("a", 0, "алгоритм: 1=Полібій координатний, 2=Полібій циклічний зсув за рядками, 3=Гронсфельд")
	lang := fs.String("lang", "", "мова/алфавіт: ua=український, lat=латинський")
	encrypt := fs.Bool("e", false, "зашифрування")
	decrypt := fs.Bool("d", false, "розшифрування")
	key := fs.String("k", "", "ключ: ключове слово квадрата (алгоритми 1-2) або рядок цифр (алгоритм 3)")
	inFile := fs.String("i", "", "читати текст з UTF-8 файла замість аргументів командного рядка")
	outFile := fs.String("o", "", "записати результат у UTF-8 файл замість стандартного виводу")
	showSquare := fs.Bool("show-square", false, "вивести у stderr побудований квадрат 6х6 (лише для алгоритмів 1-2)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	algorithm, err := algorithmFromNumber(*algoNum)
	if err != nil {
		return err
	}
	language, err := languageFromFlag(*lang)
	if err != nil {
		return err
	}
	if *encrypt == *decrypt {
		return errors.New("потрібно вказати рівно одну з опцій -e або -d")
	}

	text, err := resolveText(*inFile, fs.Args())
	if err != nil {
		return err
	}

	app := lab_2.NewContainer()

	if *showSquare && algorithm != algo.AlgorithmGronsfeld {
		sq, err := algo.BuildSquare(language, *key)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Активний квадрат:")
		fmt.Fprintln(os.Stderr, sq.String())
		fmt.Fprintln(os.Stderr)
	}

	var output string
	if *encrypt {
		res, err := app.Service.Encrypt(algorithm, language, *key, text)
		if err != nil {
			return err
		}
		output = res.Text
	} else {
		plain, err := app.Service.Decrypt(algorithm, language, *key, algo.Result{Text: text})
		if err != nil {
			return err
		}
		output = plain
	}

	if *outFile != "" {
		if err := lab_1ext.WriteUTF8File(*outFile, output); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "результат записано у %s\n", *outFile)
		return nil
	}

	fmt.Println(output)
	return nil
}

func algorithmFromNumber(n int) (algo.Algorithm, error) {
	if n < 1 || n > len(algo.Algorithms) {
		return "", fmt.Errorf("-a має бути від 1 до %d", len(algo.Algorithms))
	}
	return algo.Algorithms[n-1], nil
}

func languageFromFlag(v string) (algo.Language, error) {
	switch v {
	case "ua":
		return algo.LanguageUkrainian, nil
	case "lat":
		return algo.LanguageLatin, nil
	default:
		return "", fmt.Errorf("-lang має бути \"ua\" або \"lat\", отримано %q", v)
	}
}

func resolveText(inFile string, positional []string) (string, error) {
	if inFile != "" {
		return lab_1ext.ReadUTF8File(inFile)
	}
	if len(positional) == 0 {
		return "", errors.New("потрібно передати текст аргументом або вказати -i файл")
	}
	return strings.Join(positional, " "), nil
}

func printUsage(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, "Використання:")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/lab_2 -a=<1..3> -lang=ua|lat -e|-d -k ключ [-i вхідний.txt] [-o вихідний.txt] [-show-square] [текст]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Алгоритми:")
	for i, a := range algo.Algorithms {
		fmt.Fprintf(os.Stderr, "  %d  %s\n", i+1, a.Label())
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Опції:")
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Примітка: у координатному режимі (-a=1) текст повинен містити лише")
	fmt.Fprintln(os.Stderr, "символи обраного квадрата — приберіть пробіли та розділові знаки заздалегідь.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Приклади:")
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_2 -a=1 -lang=ua -e -k "БЕЗПЕКА" "СЛАВА"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_2 -a=1 -lang=ua -d -k "БЕЗПЕКА" "44 35 16 21 16"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_2 -a=2 -lang=ua -e -k "БЕЗПЕКА" "СЛАВА"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_2 -a=3 -lang=lat -e -k "2718" "HELLO WORLD"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_2 -a=1 -lang=ua -e -show-square -k "БЕЗПЕКА" "СЛАВА"`)
}
