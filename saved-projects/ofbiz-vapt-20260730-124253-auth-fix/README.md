# Preserved Burp run

- Source run: `artifacts/run-20260730-124253`
- Target: `https://localhost:8443/webtools/control/main`
- Burp task: `3`
- Last persisted state: `auditing`, 2% progress
- Burp project SHA-256:
  `8e1042c1846e0322758f31f5b3032aa47fbd21da68052986035838711770f15b`

The Burp process was closed before this directory was copied. The project,
REST status, Montoya bridge log, and native Burp log are preserved together.
Nothing from the earlier saved projects was removed.

After cloning on another machine:

1. Run `git lfs pull`.
2. Create the local `.env` from `.env.example` and supply that machine's Burp
   executable, REST API key, and bridge token.
3. Build with `mvn -f burp-extension/pom.xml test package`.
4. Open `burp-project.burp` with the licensed native Burp installation if this
   exact scan state needs to be inspected or resumed.

