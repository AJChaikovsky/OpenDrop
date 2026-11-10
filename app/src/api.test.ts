import { describe, expect, it } from "vitest";
import { toCssPoint } from "./api";

const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)";
const WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0";

describe("toCssPoint", () => {
  it("keeps macOS positions as they are on a Retina screen", () => {
    expect(toCssPoint({ x: 120, y: 80 }, 2, MAC)).toEqual({ x: 120, y: 80 });
  });
  it("scales Windows physical positions down to CSS pixels", () => {
    expect(toCssPoint({ x: 300, y: 150 }, 1.5, WINDOWS)).toEqual({ x: 200, y: 100 });
  });
  it("treats a missing ratio as 1", () => {
    expect(toCssPoint({ x: 10, y: 20 }, undefined, WINDOWS)).toEqual({ x: 10, y: 20 });
  });
});
