import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const respond = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") {
    return respond({ error: "Use POST" }, 405);
  }

  try {
    const { initData } = await req.json();

    if (typeof initData !== "string" || !initData || initData.length > 10000) {
      return respond({ error: "Telegram initData required" }, 400);
    }

    const botToken = Deno.env.get("TELEGRAM_BOT_TOKEN");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!botToken || !supabaseUrl || !serviceKey) {
      return respond({ error: "Server secrets are not configured" }, 500);
    }

    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");
    params.delete("hash");

    if (!receivedHash) {
      return respond({ error: "Invalid Telegram data" }, 401);
    }

    const authDate = Number(params.get("auth_date"));
    if (!Number.isFinite(authDate) ||
        Math.abs(Date.now() / 1000 - authDate) > 300) {
      return respond({ error: "Telegram login expired; try again" }, 401);
    }

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const encoder = new TextEncoder();
    const secretKey = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(botToken),
    );

    const hmacKey = await crypto.subtle.importKey(
      "raw",
      secretKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      hmacKey,
      encoder.encode(dataCheckString),
    );

    const expectedHash = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (expectedHash !== receivedHash) {
      return respond({ error: "Telegram verification failed" }, 401);
    }

    const userText = params.get("user");
    if (!userText) return respond({ error: "Telegram user missing" }, 400);

    const tgUser = JSON.parse(userText);
    if (!tgUser.id) return respond({ error: "Invalid Telegram user" }, 400);

    const db = createClient(supabaseUrl, serviceKey);

    const { data: existing, error: findError } = await db
      .from("players")
      .select("id, telegram_id, username, game_nickname, coins, inventory, is_banned")
      .eq("telegram_id", tgUser.id)
      .maybeSingle();

    if (findError) throw findError;

    let player = existing;

    if (!player) {
      const { data: created, error: createError } = await db
        .from("players")
        .insert({
          telegram_id: tgUser.id,
          username: tgUser.username ?? null,
          coins: 10,
          inventory: [],
        })
        .select("id, telegram_id, username, game_nickname, coins, inventory, is_banned")
        .single();

      if (createError) throw createError;
      player = created;
    } else if (player.is_banned) {
      return respond({ error: "Account blocked" }, 403);
    }

    return respond({
      ok: true,
      player,
      message: "Telegram verified",
    });
  } catch (error) {
    console.error(error);
    return respond({ error: "Server error" }, 500);
  }
});