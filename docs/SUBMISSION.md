# Devpost submission copy

## Project name

SentinelForge

## Track

Developer Tools

## Tagline

An autonomous security release gate that turns findings into tested patches and
proof-carrying human review.

## Description

SentinelForge helps teams secure the growing volume of machine-generated code before it
reaches production. It maps an authorized repository or staging target, runs bounded
security agents, validates findings with replayable evidence, proposes patches in an
isolated workspace, executes regression and repository tests, and produces a signed
release attestation plus an optional draft pull request.

GPT-5.6 acts as an independent evidence judge through the OpenAI Responses application
programming interface. It reviews only a redacted, allowlisted summary containing
receipt identifiers, hashes, policy decisions, test results, and the deterministic
verdict. Its strict output can approve for human review, block, or request more evidence.
It has no tools or merge authority, and code prevents it from overriding a deterministic
block.

Codex was the primary implementation partner across planning, architecture, Python
development, tests, browser interface, live deployment review, debugging, and the
OpenAI-specific extension. SentinelForge fits the Developer Tools track because it is a
runnable command line tool and release workflow for security, testing, developer
operations, agent orchestration, and pull request review.

## Repository

https://github.com/gedyeyasu/SentinelForge

## Live application

https://sentinelforge.fly.dev/

## YouTube demo

ADD_PUBLIC_YOUTUBE_LINK

## Codex feedback session

ADD_FEEDBACK_SESSION_ID
