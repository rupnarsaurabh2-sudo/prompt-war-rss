export default function handler(req, res) {
    const hasKey = Boolean(process.env.GEMINI_API_KEY);
    return res.status(200).json({
        status: "healthy",
        engine: "AegisAI Zero-Trust v4.0",
        hasKey,
        fallbackEngine: "AegisLocal-AST-v4",
        googleTech: ["Gemini 2.5 Flash", "Structured JSON Schema"]
    });
}
