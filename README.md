# 🛠️ The DevOps Journey
### From Theory to Hands — A Field Guide

> You already know *what* things are. This is about learning *what they feel like* when they're running, breaking, and being fixed at 2am.

---

## 👤 Who This Is For

Someone who can explain a TCP three-way handshake, draw a process memory layout, and describe what a context switch does — but has never stared at `strace` output wondering why a syscall is hanging. The theory is already there. This journey is the bridge.

---

## 🗺️ The Journey

```
[Phase 0] ──► [Phase 1] ──► [Phase 2] ──► [Phase 3] ──► [Phase 4] ──► [Phase 5]
  Ground         OS            Net           Infra         Reliability    You're
  Rules        Internals      Reality        as Code       Engineering   Dangerous
```

| Phase | Title | Exit Condition |
|-------|-------|----------------|
| **0** | Ground Rules: Learning to See | *"What is this machine doing right now, at every layer?"* |
| **1** | OS Internals: The Machine Is Not Magic | *"What is the OS doing on behalf of this process, and why?"* |
| **2** | Network Reality: Packets Have Mass | *"Where exactly is this network call failing, and at which layer?"* |
| **3** | Infrastructure as Code: Taming the Environment | *"Can I rebuild this entire environment from scratch in under 10 minutes?"* |
| **4** | The Deployment Pipeline: Code's Journey to Production | *"Where in the pipeline did this break, and how do I know it won't happen again?"* |
| **5** | Reliability Engineering: Designing for Failure | *"How do I know this system is healthy, and how will I know before users do when it isn't?"* |

---

## Phase 0 — Ground Rules: Learning to See

Before anything else, learn how to observe a running system. You know what a process is. Now learn to *watch* one. Learn what tools give you ground truth versus what gives you abstraction. The terminal is a microscope; most people use it as a typewriter.

*You leave this phase able to answer: "What is this machine doing right now, at every layer?"*

---

## Phase 1 — OS Internals: The Machine Is Not Magic

You've studied OS theory — scheduling, virtual memory, file descriptors, IPC. Now you make the kernel talk back to you. You'll trace syscalls, watch memory maps shift, hold open file descriptors and observe what breaks downstream. You'll see exactly where the theory lives in `/proc`.

The goal isn't to become a kernel developer. It's to never again wonder *where* something is happening — only *why*.

*You leave this phase able to answer: "What is the OS doing on behalf of this process, and why?"*

---

## Phase 2 — Network Reality: Packets Have Mass

TCP/IP is not a diagram anymore. You will capture real traffic, watch the handshake happen byte by byte, induce packet loss, and observe what the stack actually does when things go wrong — retransmits, window scaling, TIME_WAIT accumulation. You'll meet the gap between RFC behavior and production behavior.

DNS will become a source of appropriate paranoia.

*You leave this phase able to answer: "Where exactly is this network call failing, and at which layer?"*

---

## Phase 3 — Infrastructure as Code: Taming the Environment

Manual configuration is a liability. You'll learn to express machines, networks, and services as code — version-controlled, reproducible, and destroyable without regret. Containers first (because they expose OS primitives beautifully), then orchestration, then provisioning. You'll break environments on purpose, because that's how you learn what they're actually made of.

The mental shift: infrastructure is not a place, it's a *description*.

*You leave this phase able to answer: "Can I rebuild this entire environment from scratch in under 10 minutes?"*

---

## Phase 4 — The Deployment Pipeline: Code's Journey to Production

Software doesn't teleport. Between a `git push` and a running service, there's a pipeline — build, test, artifact, deploy, verify — and every step is a place things can go wrong invisibly. You'll build pipelines from nothing, instrument them, and deliberately inject failures at each stage. You'll learn what "done" actually means in production.

CI/CD is not a product. It's a discipline made visible.

*You leave this phase able to answer: "Where in the pipeline did this break, and how do I know it won't happen again?"*

---

## Phase 5 — Reliability Engineering: Designing for Failure

Systems fail. The question is whether the failure is a surprise. You'll learn observability from first principles — metrics, logs, traces — not as tools to install but as *questions you're trying to answer*. You'll define SLOs, build alerts that mean something, conduct postmortems, and practice chaos. You'll stop thinking about uptime and start thinking about error budgets.

The shift: from "prevent all failures" to "fail safely and learn faster."

*You leave this phase able to answer: "How do I know this system is healthy, and how will I know before users do when it isn't?"*

---

## ⚠️ A Note on Breaking Things

Every phase has a destruction component. This is not optional. You cannot understand a system's limits from its happy path. The moments where something refuses to work, throws an unexpected error, or behaves nothing like the documentation promised — those are the moments where real understanding is built. Break things deliberately. Break them early. Break them in controlled environments before production does it for you.

---

## 🏁 What You'll Have at the End

Not a certification. Not a list of tools you've touched. A mental model that lets you walk into any system — one you've never seen before — and start asking the right questions in the right order. The confidence that comes not from knowing everything, but from knowing how to find out.

---

> **Start with Phase 0.** Don't skip it because it sounds basic. The ability to observe clearly is the rarest skill in the field.
