"""Sensitive-column auto discovery.

The discovery pipeline never touches the source data on its own: callers
profile columns and hand the resulting shapes to the scanner. The scanner
combines sample-shape evidence with column-name evidence, keeps stable
verdicts between scans, and never overwrites human confirmations.
"""
