# cf-cloak

The tracker-blocking and data-control engine that powers [ChoiceFirst](https://choicefirst.eu).
This is the part you have to trust most, so it's the part we opened up.

---

## What's in here

DNS-level and network-level blocking rules, company identification logic, and the deletion-request automation that ChoiceFirst sends on your behalf. The app shell and backend are separate — this repo is the enforcement layer.

---

## Licensing

cf-cloak uses a **dual licensing model**.

### Open source tier — GNU AGPLv3

Free to use, study, modify, and distribute for **personal, non-commercial, and open source use**, under the terms of the [GNU Affero General Public License v3.0](LICENSE).

Key implications of AGPLv3:
- If you modify this code and run it as a service (even over a network), you must release your modifications under AGPLv3.
- You must preserve copyright and license notices.
- The full license text is in `LICENSE` and must never be modified.

### Commercial tier

Any commercial use — including but not limited to embedding cf-cloak in a paid product, SaaS offering, or enterprise deployment — requires a **separate commercial license** granted by the project owner.

Commercial inquiries: **hello@choicefirst.eu**

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting anything.

---

## Security

Found a vulnerability? Please do **not** open a public issue.
Email **security@choicefirst.eu** with details. We'll respond within 48 hours.

