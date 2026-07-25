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

    const { target, type } = await req.json(); // type: "ip", "url", "hash"

    const vtKey = Deno.env.get("VIRUSTOTAL_API_KEY");
    const abuseKey = Deno.env.get("ABUSEIPDB_API_KEY");

    let vtData = null;
    let abuseData = null;

    // AbuseIPDB (only for IPs)
    if (type === "ip" && abuseKey) {
      try {
        const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${target}&maxAgeInDays=90`, {
          headers: {
            "Key": abuseKey,
            "Accept": "application/json"
          }
        });
        if (abuseRes.ok) {
          const raw = await abuseRes.json();
          abuseData = raw?.data || null;
        }
      } catch (e) {
        console.error("AbuseIPDB error", e);
      }
    }

    // VirusTotal
    if (vtKey) {
      try {
        let vtUrl = "";
        let method = "GET";
        let fetchBody: string | URLSearchParams | null = null;
        let contentType: string | null = null;

        if (type === "ip") {
          vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${target}`;
        } else if (type === "hash") {
          vtUrl = `https://www.virustotal.com/api/v3/files/${target}`;
        } else if (type === "url") {
          vtUrl = `https://www.virustotal.com/api/v3/urls`;
          method = "POST";
          fetchBody = new URLSearchParams();
          fetchBody.append("url", target);
          contentType = "application/x-www-form-urlencoded";
        } else if (type === "analysis") {
          vtUrl = `https://www.virustotal.com/api/v3/analyses/${target}`;
        }

        if (vtUrl) {
          const headers: Record<string, string> = {
            "x-apikey": vtKey,
            "Accept": "application/json"
          };
          if (contentType) {
            headers["Content-Type"] = contentType;
          }

          const vtRes = await fetch(vtUrl, {
            method,
            headers,
            body: fetchBody
          });

          if (vtRes.ok) {
            const raw = await vtRes.json();
            if (type === "url") {
              // Return analysis ID
              vtData = { analysis_id: raw?.data?.id || null };
            } else if (type === "analysis") {
              vtData = {
                status: raw?.data?.attributes?.status || null,
                stats: raw?.data?.attributes?.results ? raw?.data?.attributes?.stats : null,
                raw_stats: raw?.data?.attributes?.stats || null
              };
            } else {
              vtData = raw?.data?.attributes?.last_analysis_stats || null;
            }
          } else {
            console.error("VT Res not ok", vtRes.status, await vtRes.text());
            if (vtRes.status === 429) {
              return new Response(JSON.stringify({ error: "quota_exceeded", status: "quota_exceeded" }), { status: 429, headers: corsHeaders });
            } else if (vtRes.status === 401 || vtRes.status === 403) {
              return new Response(JSON.stringify({ error: "authentication_failed", status: "authentication_failed" }), { status: 401, headers: corsHeaders });
            } else if (vtRes.status === 404) {
              return new Response(JSON.stringify({ error: "not_found", status: "not_found" }), { status: 404, headers: corsHeaders });
            }
          }
        }
      } catch (e) {
        console.error("VirusTotal error", e);
      }
    }

    return new Response(
      JSON.stringify({
        status: "success",
        target,
        type,
        data: {
          vt: vtData,
          abuseipdb: abuseData
        }
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
