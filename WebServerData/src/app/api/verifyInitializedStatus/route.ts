import { NextResponse } from "next/server";

export async function GET() {
    const API_RESPONSE = await fetch(`${process.env.BACKEND_API_URL}/api/backend/initializedStatus`);

    if (!API_RESPONSE.ok) {
        return NextResponse.json({ response: "Internal server error" }, { status: API_RESPONSE.status });
    }

    return NextResponse.json({ response: "Success" }, { status: 200 });
}
