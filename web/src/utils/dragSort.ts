export type DragDirection = "up" | "down" | "none";

export interface ItemRect {
  top: number;
  height: number;
}

/**
 * Computes a direction-sensitive insertion index (0..rects.length) for a
 * pointer at clientY against a vertically stacked list of resting card rects.
 *
 * Moving downward triggers insertion past a card once the pointer crosses 35%
 * of that card's height; moving upward triggers insertion before a card once
 * the pointer rises above 65% of that card's height (35% up from its bottom).
 */
export function computeDropIndex(
  rects: readonly ItemRect[],
  clientY: number,
  direction: DragDirection,
): number {
  const ratio = direction === "down" ? 0.35 : direction === "up" ? 0.65 : 0.5;
  for (let i = 0; i < rects.length; i++) {
    const threshold = rects[i].top + rects[i].height * ratio;
    if (clientY < threshold) {
      return i;
    }
  }
  return rects.length;
}

/**
 * Returns true if dropping sourceIdx at targetIdx within the same list leaves
 * the order unchanged.
 */
export function isNoOpSameListDrop(sourceIdx: number, targetIdx: number): boolean {
  return targetIdx === sourceIdx || targetIdx === sourceIdx + 1;
}

/**
 * Reorders an item from sourceIdx to insertion targetIdx (0..list.length) in a
 * single list, returning the new list and the item's final index.
 */
export function reorderList<T>(
  list: readonly T[],
  sourceIdx: number,
  targetIdx: number,
): { list: T[]; finalIndex: number; changed: boolean } {
  if (sourceIdx < 0 || sourceIdx >= list.length || isNoOpSameListDrop(sourceIdx, targetIdx)) {
    return { list: [...list], finalIndex: sourceIdx, changed: false };
  }
  const next = [...list];
  const [moved] = next.splice(sourceIdx, 1);
  const adjusted = sourceIdx < targetIdx ? targetIdx - 1 : targetIdx;
  const clamped = Math.max(0, Math.min(adjusted, next.length));
  next.splice(clamped, 0, moved);
  return { list: next, finalIndex: clamped, changed: true };
}

/**
 * Moves an item between two lists (or reorders within one list).
 */
export function moveBetweenLists<T>(
  active: readonly T[],
  inactive: readonly T[],
  sourceZone: "active" | "inactive",
  sourceIdx: number,
  targetZone: "active" | "inactive",
  targetIdx: number,
): { active: T[]; inactive: T[]; changed: boolean } {
  if (sourceZone === targetZone) {
    const base = sourceZone === "active" ? active : inactive;
    const res = reorderList(base, sourceIdx, targetIdx);
    return sourceZone === "active"
      ? { active: res.list, inactive: [...inactive], changed: res.changed }
      : { active: [...active], inactive: res.list, changed: res.changed };
  }
  const from = sourceZone === "active" ? [...active] : [...inactive];
  const to = targetZone === "active" ? [...active] : [...inactive];
  if (sourceIdx < 0 || sourceIdx >= from.length) {
    return { active: [...active], inactive: [...inactive], changed: false };
  }
  const [moved] = from.splice(sourceIdx, 1);
  const clamped = Math.max(0, Math.min(targetIdx, to.length));
  to.splice(clamped, 0, moved);
  return sourceZone === "active"
    ? { active: from, inactive: to, changed: true }
    : { active: to, inactive: from, changed: true };
}
