// Command lab_1 is a non-interactive CLI for the classic substitution and
// permutation ciphers from "Лабораторна робота 1". Cipher implementations
// live in internal/lab_1_algo; internal/lab_1 wires them into a
// CipherService (composition_root.go); UTF-8 file I/O lives in
// internal/lab_1_ext. This file only parses flags and prints results.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	lab_1 "4c-security-labs/internal/lab_1"
	algo "4c-security-labs/internal/lab_1_algo"
	lab_1ext "4c-security-labs/internal/lab_1_ext"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("lab_1", flag.ContinueOnError)
	fs.Usage = func() { printUsage(fs) }

	algoNum := fs.Int("a", 0, "алгоритм: 1=підстановка, 2=Віженер, 3=блокова перестановка, 4=вертикальна перестановка, 5=гомофонна підстановка (додатково)")
	encrypt := fs.Bool("e", false, "зашифрування")
	decrypt := fs.Bool("d", false, "розшифрування")
	key := fs.String("k", "", "ключ (якщо не задано — береться постійний ключ з .env для обраного алгоритму)")
	padding := fs.Int("p", 0, "кількість доданих символів (лише для розшифрування вертикальної перестановки)")
	inFile := fs.String("i", "", "читати текст з UTF-8 файла замість аргументів командного рядка")
	outFile := fs.String("o", "", "записати результат у UTF-8 файл замість стандартного виводу")
	freq := fs.Bool("freq", false, "додатково: вивести у stderr гістограму частот літер вхідного і вихідного тексту (розділ 13)")
	estimateKeyLength := fs.Bool("estimate-key-length", false, "додатково: не шифрувати/розшифровувати, а оцінити довжину ключа Віженера в тексті методом Касіскі та індексом збігів (разом з -a=2, розділ 13)")

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

	if *estimateKeyLength {
		if algorithm != algo.AlgorithmVigenere {
			return errors.New("-estimate-key-length застосовується лише разом з -a=2 (шифр Віженера)")
		}
		ciphertext, err := resolveText(*inFile, fs.Args())
		if err != nil {
			return err
		}
		return runEstimateKeyLength(ciphertext)
	}

	if *encrypt == *decrypt {
		return errors.New("потрібно вказати рівно одну з опцій -e або -d")
	}

	text, err := resolveText(*inFile, fs.Args())
	if err != nil {
		return err
	}

	app := lab_1.NewContainer()

	resolvedKey := *key
	if resolvedKey == "" {
		resolvedKey = app.Service.DefaultKey(algorithm)
	}

	var output string
	if *encrypt {
		res, err := app.Service.Encrypt(algorithm, resolvedKey, text)
		if err != nil {
			return err
		}
		output = res.Text
		if pad, ok := res.Meta[algo.MetaPadding]; ok {
			fmt.Fprintf(os.Stderr, "додано службових символів: %s (передайте -p %s при розшифруванні)\n", pad, pad)
		}
		if *freq {
			printFrequencyHistograms(text, output)
		}
	} else {
		in := algo.Result{Text: text}
		if algorithm == algo.AlgorithmColumnar {
			in.Meta = map[string]string{algo.MetaPadding: strconv.Itoa(*padding)}
		}
		plain, err := app.Service.Decrypt(algorithm, resolvedKey, in)
		if err != nil {
			return err
		}
		output = plain
		if *freq {
			printFrequencyHistograms(text, output)
		}
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

// runEstimateKeyLength implements the -estimate-key-length mode (section 13:
// "оцінити довжину ключа Віженера методом повторів або індексу збігів").
func runEstimateKeyLength(ciphertext string) error {
	const maxCandidateLength = 12

	bestByIC, scores := algo.EstimateVigenereKeyLengthByIC(ciphertext, maxCandidateLength)
	fmt.Printf("Оцінка за індексом збігів: довжина ключа ≈ %d\n", bestByIC)
	fmt.Println("  Середній індекс збігів для кожної довжини (1.." + strconv.Itoa(maxCandidateLength) + "):")
	for i, score := range scores {
		fmt.Printf("    %2d: %.4f\n", i+1, score)
	}

	candidates := algo.KasiskiCandidates(ciphertext, 3, maxCandidateLength)
	if len(candidates) == 0 {
		fmt.Println("Метод Касіскі: повторів довжиною від 3 літер не знайдено (текст закороткий)")
		return nil
	}
	top := candidates
	if len(top) > 5 {
		top = top[:5]
	}
	fmt.Printf("Метод Касіскі: найімовірніші довжини ключа (за кількістю голосів) — %v\n", top)
	return nil
}

// printFrequencyHistograms prints a simple bar-chart letter-frequency
// histogram for before/after text to stderr (section 13: "побудувати
// гістограму частот для відкритого тексту і шифротексту простої
// підстановки та пояснити подібність розподілів"). It works for any
// algorithm, not just substitution, but is most meaningful there since
// every other mandatory cipher either changes letter identities with a
// position-dependent shift (Vigenere) or doesn't touch letter identity at
// all (the two permutations).
func printFrequencyHistograms(before, after string) {
	fmt.Fprintln(os.Stderr, "\nГістограма частот (вхідний текст):")
	printHistogram(before)
	fmt.Fprintln(os.Stderr, "\nГістограма частот (вихідний текст):")
	printHistogram(after)
	fmt.Fprintln(os.Stderr)
}

func printHistogram(text string) {
	for _, lc := range algo.FrequencySorted(text) {
		bar := strings.Repeat("█", lc.Count)
		fmt.Fprintf(os.Stderr, "  %c %3d %s\n", lc.Letter, lc.Count, bar)
	}
}

func algorithmFromNumber(n int) (algo.Algorithm, error) {
	if n < 1 || n > len(algo.Algorithms) {
		return "", fmt.Errorf("-a має бути від 1 до %d", len(algo.Algorithms))
	}
	return algo.Algorithms[n-1], nil
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
	fmt.Fprintln(os.Stderr, "  go run ./cmd/lab_1 -a=<1..5> -e|-d [-k ключ] [-p N] [-i вхідний.txt] [-o вихідний.txt] [-freq] [текст]")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/lab_1 -a=2 -estimate-key-length [-i шифротекст.txt] [шифротекст]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Алгоритми:")
	for i, a := range algo.Algorithms {
		fmt.Fprintf(os.Stderr, "  %d  %s\n", i+1, a.Label())
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Опції:")
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Приклади:")
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=2 -e "СЛАВА УКРАЇНІ"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=2 -d "ВЬЮЩК ДЇККЧЛД"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=4 -d -p 2 "ШИФРОТЕКСТ"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=5 -e "ПРИВІТ"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=1 -e -freq "СЛАВА УКРАЇНІ"`)
	fmt.Fprintln(os.Stderr, `  go run ./cmd/lab_1 -a=2 -estimate-key-length -i ciphertext.txt`)
}
