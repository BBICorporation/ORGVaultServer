import jwt from "jsonwebtoken";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
    const REQUEST_DATA = await req.json();
    const MAC_ADDRESS = REQUEST_DATA.adminMacAddress;
    const KEY_BIN_HASH = process.env.KEY_BIN_HASH;

    if (!KEY_BIN_HASH) {
        return NextResponse.json({ response: "Invalid key bin hash" }, { status: 500 });
    }

    const MAC_ADDRESS_FORMAT = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

    // Checking format
    if (!MAC_ADDRESS && !MAC_ADDRESS_FORMAT.test(MAC_ADDRESS)) {
        return NextResponse.json({ response: "Invalid admin mac address" }, { status: 401 });
    }

    // Verifying mac address with backend
    try {
        const BACKEND_API_RESPONSE = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_API_URL}/api/backend/verifyAdminMac`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                adminMacAddress: MAC_ADDRESS,
                keyBinHash: KEY_BIN_HASH,
            }),
        });

        if (!BACKEND_API_RESPONSE.ok) {
            const BACKEND_API_RESPONSE_DATA = await BACKEND_API_RESPONSE.json();

            return NextResponse.json({ status: BACKEND_API_RESPONSE.status, response: BACKEND_API_RESPONSE_DATA.response });
        }
    } catch (e) {
        return NextResponse.json({ response: `Internal server error` }, { status: 500 });
    }

    const TOKEN = jwt.sign({ MAC_ADDRESS: MAC_ADDRESS }, KEY_BIN_HASH, { expiresIn: "7d" });

    let returnSuccess = NextResponse.json({ response: "Success" }, { status: 200 });
    returnSuccess.cookies.set("token", TOKEN, { httpOnly: true, sameSite: "strict", maxAge: 7 * 24 * 60 * 60 * 1000, secure: process.env.NODE_ENV === "production", path: "/" });

    // Return
    return returnSuccess;
}
