# AbuseCLI

A command-line tool for interacting with [AbuseIPDB](https://www.abuseipdb.com/). Check IPs, report abuse, filter results, and export data — all from your terminal.

---

## Installation

```bash
pip install -r requirements.txt
```

You'll need an AbuseIPDB account and an API key. Get one at [abuseipdb.com/api](https://www.abuseipdb.com/api).

On first run the tool will ask for your key and offer to save it to a `.env` file so you never have to type it again. You can also set it yourself:

```bash
echo "ABUSEIPDB_API_KEY=your_key_here" > .env
```

---

## Usage

```
python abusecli.py <command> [options]
```

There are four commands: `check`, `report`, `load`, and `categories`.

---

## check

Look up one or more IPs and see their abuse score, country, TOR status, and recent report activity.

```bash
# one IP
python abusecli.py check --ips 185.220.101.1

# several at once
python abusecli.py check --ips 8.8.8.8 1.1.1.1 185.220.101.1

# from a text file, one IP per line (# comments are ignored)
python abusecli.py check --from-file blocklist.txt
```

Results come back as a table. Use `--verbose` if you want to see the actual reports behind the score — reporter country, categories, comments, timestamps.

You can narrow results with filters like `--score 50` (only IPs above a threshold), `--risk-level high`, `--country-code DE`, `--is-tor`, and a few others. Run `--help` to see the full list.

You can also control how far back the tool looks for reports with `--max-age` (in days, default is 90).

### Exporting

Add `--export` to save results to a file. You can combine formats:

```bash
python abusecli.py check --from-file blocklist.txt --export csv json
```

Supported formats: `csv`, `json`, `excel`, `html`, `parquet`.

---

## report

Submit abuse reports to AbuseIPDB. Every report needs at least one category ID — run `python abusecli.py categories` to see the full list.

```bash
python abusecli.py report --ips 185.220.101.1 --categories 18 22 --comment "SSH brute force"
```

Before anything is sent, you'll see a confirmation table showing exactly what will be reported. Type `y` to proceed or `N` to cancel.

### Reporting from a file

If you just ran a `check` and exported the results, you can feed that file straight into `report`:

```bash
python abusecli.py report --source ip_check_20240101.csv --categories 18 22
```

Use `--min-score 75` to only report IPs above a certain confidence threshold — useful when your export contains a mix of low and high-risk IPs and you only want to act on the clear-cut ones.

### Dry run

Not sure yet? Use `--dry-run` to preview the full batch without submitting anything:

```bash
python abusecli.py report --source results.csv --categories 18 --dry-run
```

---

## load

Reload a previously exported file, apply filters, and re-export. Useful for slicing up a large export after the fact without hitting the API again.

```bash
python abusecli.py load --source ip_check_20240101.csv --risk-level critical --export json
```

Accepts the same filters as `check`. Required columns are `ipAddress` and `abuseConfidenceScore` — everything else is optional.

---

## categories

Prints the full list of AbuseIPDB category IDs and their names. Handy when writing a report and you can't remember which ID is which.

```bash
python abusecli.py categories
```

---

## Project structure

```
abusecli.py          entrypoint
abusecli/
  api.py             AbuseIPDB HTTP calls
  auth.py            API key loading and storage
  commands.py        one function per subcommand
  constants.py       risk thresholds, category IDs, defaults
  data.py            filtering and DataFrame enrichment
  display.py         tables, panels, and all terminal output
  io.py              file import and export
  main.py            argument dispatch
  parser.py          CLI argument definitions
```