import httpx

def score(text):
    r = httpx.post("http://localhost:8000/api/v1/lab/scan/text", json={"text": text}, timeout=120)
    d = r.json()
    p = d.get("phishing_probability", -1)
    v = d.get("verdict", d.get("detail", "ERR"))
    print(f"  {p:.4f}  {v:<12}  '{text}'")

print("--- isolating which part triggers it ---")
score("hi my name is suhani buche")
score("hi my name is john smith")
score("hi my name is alice")
score("my name is suhani")
score("hi my name is")
score("my name is")
score("suhani buche")
score("hi suhani")
score("hello i am suhani")
score("hi i am suhani buche from support please verify your account")
