# Parental Control — Proof of Concept

This repository contains the initial **Proof of Concept (PoC)** for our Magshimim project.

The goal of the project is to develop a **Linux-based parental control system** that allows a parent to monitor and control the internet activity of a computer.

The application will maintain a browsing history, allow parents to define websites that should be blocked, and automatically block websites according to the project's content-detection criteria.

A central technical aspect of the project is investigating the difference between the internal state of the Linux kernel and the information exposed to usermode. This will serve as the technical foundation for the monitoring component of the parental-control system.

---

## Project Structure

The PoC is divided into two main components, each demonstrating a different part of the project's core functionality.

```text
.
├── process-hiding/
│   ├── project-rvbbit/
│   │   └── Copy of the RVBBIT repository
│   └── wrapper/
│       └── Installer and test application
└── network-monitoring/
    └── Network sniffing & firewall management
```

---

## 1. Process Hiding

The `process-hiding/` folder contains the PoC for the project's central process-visibility concept.

### `project-rvbbit/`

This folder contains a copy of the existing **Project RVBBIT** PoC (https://github.com/buter-chkalova/project-rvbbit).

It demonstrates kernel-level process hiding by manipulating the way a process is represented and exposed to usermode. The PoC allows us to verify that a process can remain active within the kernel while becoming hidden from standard usermode process interfaces.

We use this as the initial proof that the core process-hiding concept of the project is technically feasible.

### `wrapper/`

This folder contains the code that wraps the RVBBIT PoC for our own testing.

It will contain the installer and a simple test application that is used as the target process for the hiding mechanism.

The purpose of the wrapper is to provide a simple and controlled way to run the PoC and demonstrate its effect, without modifying the original RVBBIT repository.

---

## 2. Network Monitoring

The `network-monitoring/` folder contains the PoC for the networking-related functionality of the parental-control application.

This component will be implemented primarily in **Python**, using existing libraries and Linux interfaces where appropriate.

### Network Sniffing

The application will monitor relevant network traffic and collect information about websites accessed by the computer.

HTTP traffic can provide more detailed information, while HTTPS provides more limited information. Where possible, the system will identify the domain being accessed.

The collected information will be sent to the server through a socket, where it will be stored as part of the browsing history.

### Firewall Management

The application will also manage firewall rules used to block websites.

Parents will be able to manually specify domains that should be blocked, while the application may also identify websites that should be blocked automatically according to the project's content-detection criteria.

When a domain is blocked, the application will add an appropriate rule to the system firewall to prevent access to it.

---

## Current Status

* [ ] Process hiding PoC using Project RVBBIT
* [ ] Wrapper for running and testing the process-hiding PoC
* [ ] Independent process hiding implementation
* [ ] Network hiding PoC
* [ ] Python network sniffing
* [ ] Socket communication with server
* [ ] Browsing history
* [ ] Python firewall management
* [ ] Manual domain blocking
* [ ] Automatic content-based blocking
* [ ] Integration of components

> **Project objective:** Develop a functional Linux parental-control system while exploring how the Linux kernel's internal state can differ from the information exposed to usermode.
