# Getting Started: Try the IOC Lookup Tool

**No technical background needed.** This guide walks you through everything, one small step at a time. It takes about 20 minutes, and most of that is signing up for two free accounts.

---

## What does this tool do?

Imagine you get a suspicious email, or your computer security software flags a weird file. Security analysts need a quick way to ask: *"Has anyone else seen this before, and is it known to be dangerous?"*

This tool answers that question. You give it something suspicious, and it asks two big security databases (**VirusTotal** and **AbuseIPDB**) what they know. Then it gives you a simple verdict:

| Verdict | Meaning |
|---------|---------|
| **CLEAN** | Security engines found nothing wrong |
| **SUSPICIOUS** | A few engines flagged it. Be careful and investigate further |
| **MALICIOUS** | Many engines flagged it. Treat it as dangerous |
| **UNKNOWN** | The databases have never seen it |

### What can you look up?

- **A file hash**: a long code (like `275a021b...`) that works as a fingerprint for a file
- **An IP address**: like `8.8.8.8`
- **A domain**: like `example.com`
- **A web link (URL)**: like `https://example.com/login`

### Is it safe?

Yes. The tool only **looks things up**. It never opens files, runs anything dangerous, or visits suspicious websites. The first test uses a **harmless** fake "virus" file that exists only for testing.

One privacy rule: **don't look up private or confidential information** (like your company's internal server names), because lookups go to public services.

---

## Before you start

You'll need:

- A computer (Windows or Mac)
- An internet connection
- An email address (to make free accounts)

---

## Step 1: Put the tool in a folder

1. Download all the project files into a **new folder** on your computer. Call it `ioc-lookup`.
2. You should see these files inside: `ioc_lookup.py`, `requirements.txt`, `.env.example`, `.gitignore`, `sample_iocs.txt`.

> **Can't see `.env.example`?** Files starting with a dot are hidden on some computers. That's fine. We'll handle it with a command later.

---

## Step 2: Install Python

Python is the free language this tool is written in. Your computer needs it to run the tool.

**Check if you already have it:**

1. Open a **terminal** (a window where you type commands):
   - **Windows:** press the Windows key, type `cmd`, press Enter.
   - **Mac:** press Cmd + Space, type `Terminal`, press Enter.
2. Type this and press Enter:
   - **Windows:** `python --version`
   - **Mac:** `python3 --version`

If you see something like `Python 3.11.4`, skip ahead to Step 3. Any version 3.8 or higher works.

**If you get an error, or the Microsoft Store opens:**

1. Go to **python.org/downloads** and download the latest version.
2. Run the installer.
3. **Windows only:** on the first screen, tick the box that says **"Add Python to PATH"** before clicking Install. This is important.
4. When it finishes, close your terminal and open a new one, then try the version check again.

---

## Step 3: Open a terminal inside your folder

**Windows:**
1. Open the `ioc-lookup` folder in File Explorer.
2. Click the **address bar** at the top (where the folder path is shown).
3. Type `cmd` and press Enter. A black window opens, already in the right place.

**Mac:**
1. Open Terminal.
2. Type `cd ` (the letters c, d, and then a space). Don't press Enter yet.
3. Drag the `ioc-lookup` folder from Finder into the Terminal window. The folder path appears.
4. Press Enter.

**Check you're in the right place.** Type `dir` (Windows) or `ls` (Mac) and press Enter. You should see `ioc_lookup.py` in the list.

> **Tip:** From now on, **Mac users should type `python3` and `pip3`** wherever this guide says `python` and `pip`.

---

## Step 4: Install the helper pieces

The tool uses two small add-ons. Install both with one command:

```
pip install -r requirements.txt
```

You'll see text scroll by. Wait until you get your cursor back. Seeing "Successfully installed" means it worked.

---

## Step 5: Get your free API keys

An **API key** is like a personal password that lets the tool talk to a service on your behalf. Both services are free.

### VirusTotal (required)

1. Go to **virustotal.com** and click **Sign up**.
2. Create an account and confirm your email.
3. Click your **profile icon** (top right) and choose **API key**.
4. Click the **copy** button next to the long code. Paste it somewhere temporary, like a notepad.

### AbuseIPDB (optional, but recommended for IP addresses)

1. Go to **abuseipdb.com** and click **Sign up**.
2. Create an account and confirm your email.
3. Open your **Account** page, then the **API** tab.
4. Click **Create Key** and copy it.

> **Treat keys like passwords.** Don't share them, post them online, or send them in messages.

---

## Step 6: Save your keys in the tool

We'll create a settings file called `.env` from the template. In your terminal:

**Windows:**
```
copy .env.example .env
notepad .env
```

**Mac:**
```
cp .env.example .env
open -e .env
```

A text editor opens with two lines:

```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here_optional
```

1. Delete `your_virustotal_key_here` and paste your VirusTotal key in its place.
2. Do the same with your AbuseIPDB key. If you skipped AbuseIPDB, just leave that line alone.
3. **No spaces and no quote marks.** It should look like `VT_API_KEY=abc123yourlongkey`.
4. Save the file (Ctrl+S or Cmd+S) and close the editor.

---

## Step 7: Run your first lookup

Now the fun part. This checks the **EICAR test file**, a harmless fake virus that security software flags on purpose, so it's perfect for practice.

Copy this whole line into your terminal and press Enter:

```
python ioc_lookup.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

After a few seconds you should see a report like this (your numbers will differ):

```
============================================================
Indicator : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Type      : hash
VERDICT   : MALICIOUS
------------------------------------------------------------
VirusTotal
  Detections: 60 malicious, 0 suspicious, 0 harmless, 10 undetected
  ...
```

**Congratulations, you just did a real security lookup.**

### How to read the report

- **Indicator:** what you asked about
- **Type:** what the tool decided it was (hash, IP, domain, or URL)
- **VERDICT:** the simple answer
- **Detections:** how many security engines said "malicious" vs. "clean." Roughly 70 engines check each item.

---

## Step 8: Try other lookups

Each of these works the same way. Run them one at a time:

**An IP address** (Google's public DNS server, which is safe):
```
python ioc_lookup.py 8.8.8.8
```

**A domain:**
```
python ioc_lookup.py example.com
```

**A web link.** Put quote marks around links:
```
python ioc_lookup.py "https://example.com"
```

**Your own suspicious item.** Replace the example with whatever you want to check:
```
python ioc_lookup.py PASTE_HERE
```

> **Handy trick:** Security reports often write dangerous links in a "defanged" way, like `hxxps://bad-site[.]com`, so nobody clicks them by accident. You can paste those straight in. The tool understands them.

---

## Step 9: Check many things at once

Open `sample_iocs.txt` in any text editor. Each line is one item to check. Lines starting with `#` are notes and get ignored. Add your own items on new lines.

Then run:

```
python ioc_lookup.py -f sample_iocs.txt --csv results.csv
```

Two things to know:

- **It pauses about 15 seconds between lookups.** That's on purpose. The free VirusTotal plan only allows about 4 questions per minute, and the pause keeps you under the limit. You'll see a "waiting" message.
- **`--csv results.csv` saves a spreadsheet.** After it finishes, find `results.csv` in your folder and open it in Excel or Google Sheets.

Run the same command again and notice how fast it is. The tool remembers answers for 24 hours so it doesn't use up your daily limit.

---

## Troubleshooting

| What you see | What it means | Fix |
|---|---|---|
| `'python' is not recognized` (Windows) | Python isn't installed or wasn't added to PATH | Reinstall Python and tick **"Add Python to PATH"**. Open a new terminal afterward |
| `command not found: python` (Mac) | Mac uses a different name | Type `python3` instead |
| `'pip' is not recognized` | Same as above | Try `python -m pip install -r requirements.txt` (Mac: `python3 -m pip ...`) |
| `ModuleNotFoundError` | Step 4 didn't finish | Run `pip install -r requirements.txt` again |
| `Missing VT_API_KEY` | The tool can't find your key | Make sure the file is named `.env` (not `.env.txt`) and sits in the same folder as `ioc_lookup.py` |
| `invalid VirusTotal API key` | The key was pasted wrong | Re-copy it from VirusTotal. Check for stray spaces or quote marks |
| `VirusTotal rate limit hit` | You asked too many questions too quickly | Wait a minute and try again |
| `Not found in VirusTotal` | VirusTotal has never seen this item | Not an error. It just means there's no information |
| Verdict says `INVALID` | The tool couldn't tell what you typed | Check for typos. Put links in quote marks |

Still stuck? Copy the full error message from your terminal. That text is the best clue for anyone helping you.

---

## A few words of caution

- **Never open or run a file just because you're curious about it.** This tool checks a file's *fingerprint* (hash), so you never need to open the file itself.
- **A CLEAN verdict is not a guarantee.** Brand-new threats may not be known yet.
- **A SUSPICIOUS verdict is not proof of danger.** Sometimes a single engine is simply wrong (a "false positive"). Analysts look at the details before deciding.
- **Keep your `.env` file private.** It contains your keys.

---

## What next?

- Read [README.md](README.md) to learn how the tool works under the hood.
- Look up real indicators from public threat reports (try searching for "threat report IOCs").
- Curious about security careers? This kind of lookup is something SOC analysts do many times a day.

Happy investigating!
