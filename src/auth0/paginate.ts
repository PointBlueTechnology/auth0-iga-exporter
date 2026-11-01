/** Walk an Auth0 SDK page. Stops if a response stream runs away. */
export async function drain<T>(page: AsyncIterable<T>, maxItems = 100_000): Promise<T[]> {
  const items: T[] = [];
  for await (const item of page) {
    items.push(item);
    if (items.length > maxItems) {
      throw new Error(`stopped after ${maxItems} records; pagination did not end`);
    }
  }
  return items;
}
