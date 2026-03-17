import express from "express";
import OpenAI from "openai";

const router = express.Router();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

router.post("/query", async (req, res) => {

  try {

    const { question } = req.body;

    if (!question) {
      return res.status(400).json({
        error: "Question required"
      });
    }

    const systemPrompt = `
You are QIE (QuantumMail Intelligence Engine).

Your job is to explain:

- QuantumMail encryption
- device trust model
- organization security
- AES envelope encryption
- RSA key wrapping

You must NEVER access plaintext messages.
QuantumMail stores encrypted content only.
`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: question }
      ]
    });

    res.json({
      answer: completion.choices[0].message.content
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "QIE failure"
    });

  }

});

export default router;
