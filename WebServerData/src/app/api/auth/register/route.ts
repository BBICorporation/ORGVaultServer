import jwt from "jsonwebtoken";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
    const REQUEST_DATA = await req.json();
    const MAC_ADDRESS = REQUEST_DATA.adminMacAddress;
    const USERNAME = REQUEST_DATA.username;
    const PASSWORD = REQUEST_DATA.password;
    const KEY_BIN_HASH = process.env.KEY_BIN_HASH;

    // Checking if data is complete
    if (!KEY_BIN_HASH) {
        return NextResponse.json({ response: "Invalid key bin hash" }, { status: 500 });
    }

    if (!MAC_ADDRESS || !USERNAME || !PASSWORD) {
        return NextResponse.json({ response: "Invalid request data" }, { status: 400 });
    }

    const MAC_ADDRESS_FORMAT = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

    if (!MAC_ADDRESS && !MAC_ADDRESS_FORMAT.test(MAC_ADDRESS)) {
        return NextResponse.json({ response: "Invalid admin mac address" }, { status: 401 });
    }

    try {
        const API_RESPONSE = await fetch(`${process.env.BACKEND_API_URL}/api/backend/initializeServer`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                macAddress: MAC_ADDRESS,
                username: USERNAME,
                password: PASSWORD,
                keyBinHash: KEY_BIN_HASH,
            }),
        });

        if (!API_RESPONSE.ok) {
            const API_RESPONSE_DATA = await API_RESPONSE.json();

            return NextResponse.json({ response: API_RESPONSE_DATA.response }, { status: API_RESPONSE.status });
        }
    } catch (e) {
        return NextResponse.json({ response: `Internal server error` }, { status: 500 });
    }

    // Setting jwt and returning response
    const TOKEN = jwt.sign({ MAC_ADDRESS: MAC_ADDRESS }, KEY_BIN_HASH, { expiresIn: "7d" });

    let returnSuccess = NextResponse.json({ response: "Success" }, { status: 200 });
    returnSuccess.cookies.set("token", TOKEN, { httpOnly: true, sameSite: "strict", maxAge: 7 * 24 * 60 * 60 * 1000, secure: process.env.NODE_ENV === "production", path: "/" });

    // Return
    return returnSuccess;
}
