# Timely Pass: Time-based Password manager

Timely Pass allows the user to set dynamic passwords with custom policies on their computer based on time constraitns.

## Hooks

The basic hooks rely on they type `Period`, which is an enum of `Time` and `Date` types.
These Hooks are:
1. `onlyBefore`: Only accept this password before `Period`.
2. `onlyAfter`: Only accept this password after `Period`.
3. `onlyWithin`: Only accept this password within `Period`.
4. `onlyFor`: Only accept this password for `Period`.

How it works: Time (at so so time/date, rotate acceptable password to only this password/mechanism).

# By [Balqaasem](https://balqaasem.xyz)
