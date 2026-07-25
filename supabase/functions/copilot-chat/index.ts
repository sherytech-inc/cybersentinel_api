import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Missing authorization" }), { status: 401, headers: corsHeaders });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    // Verify user
    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Invalid user token" }), { status: 401, headers: corsHeaders });
    }

    const { session_id, message, system_prompt, context_data } = await req.json();
    
    const groqKey = Deno.env.get("GROQ_API_KEY");
    if (!groqKey) {
        throw new Error("GROQ_API_KEY is not configured");
    }

    const messages = [];
    if (system_prompt) {
        messages.push({ role: "system", content: system_prompt });
    }
    if (context_data) {
        messages.push({ role: "system", content: `Context:\n${JSON.stringify(context_data)}` });
    }
    messages.push({ role: "user", content: message });

    const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${groqKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            model: "llama3-8b-8192",
            messages: messages,
            temperature: 0.7,
            max_tokens: 1024
        })
    });

    if (!groqRes.ok) {
        const errText = await groqRes.text();
        throw new Error(`Groq API error: ${errText}`);
    }

    const groqData = await groqRes.json();
    const reply = groqData.choices?.[0]?.message?.content || "No response generated.";

    return new Response(
      JSON.stringify({
        session_id,
        response: reply,
        timestamp: new Date().toISOString()
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  } catch (error: any) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: corsHeaders,
    });
  }
});
