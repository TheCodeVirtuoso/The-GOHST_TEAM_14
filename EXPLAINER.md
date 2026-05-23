# What We Did — In Plain English
### JWT Hacking Demo · TEAM-14 · Amrita School of Computing

---

## What is a JWT? (The Simple Version)

When you log into a website, the server gives you a **digital pass** — like a wristband at a concert.

Every time you visit a page that needs login, you show that wristband.  
The server checks it and lets you in.

That wristband is called a **JWT (JSON Web Token)**.

It has three parts:
- **Who you are** — your username and role (e.g. regular user or admin)
- **A stamp of approval** — a digital signature proving the server issued it
- **An expiry** — when the pass stops working *(if the server bothers to set one)*

---

## The Problem We Found

The server we built on purpose has **one big mistake:**

> It lets the user decide how to verify their own wristband.

That is like a bouncer saying:  
*"Hey, how should I check if your wristband is real?"*  
And the user replies: *"Don't check it. Just trust me."*  
And the bouncer says: *"Okay, you're in."*

---

## Attack 1 — The "Just Trust Me" Attack

**What we did:**  
We told the server **"don't check the signature"** — and it listened.

**Real life analogy:**  
Imagine a VIP club where the bouncer reads a note on your wristband that says  
*"No need to verify this."*  
So he just lets you in — no checking, no scanning, nothing.

**What happened:**  
We wrote our own wristband that said **"I am admin"**  
with a note that said **"no signature needed"**  
and the server gave us full admin access.

> **Result:** We got the secret flag without knowing any password or secret key.

---

## Attack 2 — The "Wrong Lock, Right Key" Attack

**What we did:**  
We tricked the server into using the **wrong method** to check our wristband —  
a method where we already knew the answer.

**Real life analogy:**  
A bank has two locks on the vault:
- Lock A needs a **private key** (only the bank has it)
- Lock B needs a **public key** (everyone can see it on the website)

The bank accidentally checks both locks the same way.  
We switched our wristband label from Lock A to Lock B.  
Now we use the public key — which is freely available — to open the vault.

**What happened:**  
We downloaded the server's public key (it is meant to be public).  
We used it to sign our own fake wristband.  
The server checked it, matched, and let us in as admin.

> **Result:** Admin access — using only information that was already public.

---

## Attack 3 — The "I Am Whoever I Say I Am" Attack

**What we did:**  
Once the server stopped checking signatures (Attack 1 or 2),  
we could write **anything we wanted** inside the wristband.

**Real life analogy:**  
Imagine a wristband you write yourself with a marker.  
It says **"VIP — All Access."**  
The bouncer doesn't look at where it came from — just reads what it says.

**What happened:**  
We changed the wristband to say `role: admin`  
The server read it, trusted it, and gave us the admin page.

> **Result:** Any user can pretend to be any other user — or an admin — instantly.

---

## Attack 4 — The "Keep Guessing Passwords" Attack

**What we did:**  
We tried common passwords on multiple accounts — slowly, so no alarm triggered.

**Real life analogy:**  
Instead of trying 1000 passwords on one door (which triggers an alarm),  
we try 3 passwords on 100 different doors.  
Statistically, some doors open.

**What happened:**  
We tried passwords like `password`, `123456`, `secret` across accounts.  
We found:
- `admin` with password `secret99` → got in
- `alice` with password `pass123` → got in

> **Result:** Real account credentials captured without triggering any lockout.

---

## Attack 5 — The "Crack the Secret Code" Attack

**What we did:**  
Some servers use a **short password** to protect all their tokens.  
We guessed that password — completely offline, without even touching the server.

**Real life analogy:**  
Imagine every wristband at the concert is stamped with a seal.  
The seal is made with a rubber stamp that says **"hackme"**.  
If you find the rubber stamp, you can stamp your own wristbands.  
We found the stamp by trying common words until one matched.

**What happened:**  
We took one captured token, tried 15 common words,  
and found the secret was `"hackme"`.  
Now we can stamp any wristband we want.

> **Result:** Ability to forge unlimited valid tokens — for any user, any role.

---

## Attack 6 — The "Old Ticket Still Works" Attack

**What we did:**  
We used the **same login pass over and over** — days after we first got it.

**Real life analogy:**  
You buy a one-day concert ticket.  
You come back the next week.  
The scanner just checks if the ticket looks real — not when it was bought.  
It lets you in every time.

**What happened:**  
We logged in as `alice` once and saved the token.  
We used that same token 5 times in a row.  
The server accepted it every single time — no questions asked.

> **Result:** Anyone who gets your token once can use it forever.

---

## How Do We Know These Are Real Problems?

These are not made-up attacks. They have happened in the real world:

- **2015** — A bug exactly like Attack 1 and 2 was found in a library used by millions of websites. *(CVE-2015-9235)*
- **2022** — Auth0, a major login provider used by thousands of companies, had the same algorithm confusion bug we demonstrated.
- **AWS, Google, Microsoft** — all major cloud platforms use the same type of tokens. If misconfigured the same way, the same attacks work.

---

## The Fix (Also Simple)

The entire JWT attack (Attacks 1, 2, and 3) is fixed with **one line of code:**

> *"Only accept tokens signed with RS256. Reject everything else."*

That one change makes the server ignore any attempt to switch algorithms or skip signatures.

For the other attacks:
- **Credential spray** → limit how many times someone can try to log in per minute
- **Token replay** → add an expiry time to every token (like a concert ticket date)

---

## What We Built

| Thing | What it does |
|-------|-------------|
| Vulnerable server | A login system with the mistake built in — attacks work here |
| Hardened server | Same system with the one-line fix — attacks are blocked here |
| 6 attack scripts | One script per attack — shows exactly how each exploit works |
| Live dashboard | A website showing attacks happening in real time, from any laptop |

---

## The Key Takeaway

> A server that lets users choose how their own identity is verified  
> is like a passport control officer who asks:  
> *"Should I check your passport, or do you want to just walk through?"*
>
> One small configuration mistake.  
> No password needed. No hacking tools needed.  
> Just a text editor and basic math.
