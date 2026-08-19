import { describe, it, expect } from "vitest";
import { scoreLabel, scoreBand } from "./scoreLabel";

describe("scoreLabel/scoreBand", () => {
  it("matches the thresholds previously duplicated across Dashboard/Onboarding/Project pages", () => {
    expect(scoreLabel(100)).toBe("READY");
    expect(scoreLabel(90)).toBe("READY");
    expect(scoreLabel(89)).toBe("REVIEW");
    expect(scoreLabel(75)).toBe("REVIEW");
    expect(scoreLabel(74)).toBe("NEEDS WORK");
    expect(scoreLabel(50)).toBe("NEEDS WORK");
    expect(scoreLabel(49)).toBe("NOT READY");
    expect(scoreLabel(0)).toBe("NOT READY");
  });

  it("scoreBand's CSS-class suffix matches the same thresholds as scoreLabel", () => {
    expect(scoreBand(95)).toBe("ready");
    expect(scoreBand(80)).toBe("review");
    expect(scoreBand(60)).toBe("work");
    expect(scoreBand(10)).toBe("bad");
  });
});
