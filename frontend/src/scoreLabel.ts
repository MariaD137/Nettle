// Shared score-band logic — previously duplicated verbatim across
// DashboardPage, OnboardingPage, and ProjectPage (three copies of the same
// 90/75/50 thresholds, already drifted into inconsistent styles). One
// source of truth for both the human-readable label and the CSS class
// suffix that colors it.
export type ScoreBand = "ready" | "review" | "work" | "bad";

export function scoreBand(score: number): ScoreBand {
  if (score >= 90) return "ready";
  if (score >= 75) return "review";
  if (score >= 50) return "work";
  return "bad";
}

export function scoreLabel(score: number): string {
  switch (scoreBand(score)) {
    case "ready":
      return "READY";
    case "review":
      return "REVIEW";
    case "work":
      return "NEEDS WORK";
    case "bad":
      return "NOT READY";
  }
}
