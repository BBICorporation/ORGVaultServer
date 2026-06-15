import jwt from "jsonwebtoken";
import { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
    const REQUEST_DATA = await req.json();
    const MAC_ADDRESS = REQUEST_DATA.adminMacAddress;


}
