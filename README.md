# MigrateNessus
migrateNessus.py is an API script used to migrate nessus scans and policies from one Nessus 6 host to another.

To be clear, this does not transfer over user accounts.
Credentials and audit files do not transfer with the policies.
Likewise, schedules do not transfer over with the scan results.

The user will still need to set up all the Advanced settings in Nessus as those do not transfer over either.

As of right now, this script only transfers Nessus scans and policies in .Nessus format.
