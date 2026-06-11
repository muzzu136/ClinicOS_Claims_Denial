---
name: browser
description: Automate web browser interactions using the browse CLI. Use when you need to inspect live pages, verify deployments, scrape content, look up documentation, fill forms, click buttons, or interact with web applications.
---

# Browser Automation (browse CLI)

Automate browser interactions using the `browse` CLI. The browser connects to
Browserbase (remote) automatically via `BROWSERBASE_API_KEY`.

## Setup check

```bash
which browse || echo "browse CLI not found"
```

## Workflow

1. `browse open <url>` — navigate (auto-starts browser daemon)
2. `browse snapshot -c` — read the accessibility tree with element refs
3. `browse click <ref>` / `browse type <text>` / `browse fill <selector> <value>` — interact
4. `browse snapshot -c` — confirm the action worked
5. Repeat 3-4 as needed
6. `browse stop` — close the browser when done

Always `browse stop` when done to free resources.

## Commands

### Navigation

```bash
browse open <url>                          # Go to URL (auto-starts daemon)
browse open <url> --wait networkidle       # Wait for all network requests (SPAs)
browse open <url> --wait domcontentloaded  # Wait for DOM only
browse reload                              # Reload current page
browse back                                # Go back in history
browse forward                             # Go forward in history
```

### Page State (prefer snapshot over screenshot)

```bash
browse snapshot -c         # Accessibility tree with element refs (fast, structured)
browse screenshot [path]   # Visual screenshot (slow, uses vision tokens)
browse screenshot --full-page  # Full scrollable page
browse get url             # Current URL
browse get title           # Page title
browse get text <selector> # Text content (use "body" for all text)
browse get html <selector> # HTML content of element
browse get value <selector># Form field value
browse get box <selector>  # Bounding box (centroid coordinates)
```

Use `browse snapshot -c` as your default. Only screenshot when you need visual context.

### Interaction

```bash
browse click <ref>                # Click by ref from snapshot (e.g. @0-5)
browse click_xy <x> <y>          # Click at coordinates
browse type <text>                # Type into focused element
browse type <text> --delay 100   # Type with delay between keystrokes
browse fill <selector> <value>   # Fill input and press Enter
browse fill <selector> <value> --no-press-enter  # Fill without Enter
browse select <selector> <values...>  # Select dropdown option(s)
browse press Enter                # Press key (Enter, Tab, Escape, Cmd+A, etc.)
browse scroll <x> <y> <deltaX> <deltaY>  # Scroll at position
browse drag <fromX> <fromY> <toX> <toY>  # Drag between coordinates
browse hover <x> <y>             # Hover at coordinates
browse wait load                  # Wait for page load
browse wait selector <selector>   # Wait for element to appear
browse wait timeout <ms>          # Wait N milliseconds
```

### JavaScript Evaluation

```bash
browse eval "document.title"
browse eval "document.querySelectorAll('a').length"
```

### Session Management

```bash
browse stop              # Stop browser daemon (always do this when done)
browse stop --force      # Force kill if unresponsive
browse status            # Check daemon status
browse pages             # List all open tabs
browse newpage [url]     # Open new tab
browse tab_switch <n>    # Switch to tab by index
browse tab_close [n]     # Close tab
```

### Network Capture

```bash
browse network on        # Start capturing requests
browse network off       # Stop capturing
browse network path      # Get capture directory
browse network clear     # Clear captured requests
```

## Element References

After `browse snapshot`, elements have refs like `@0-5`:

```
RootWebArea "Example" url="https://example.com"
  [0-0] link "Home"
  [0-1] link "About"
  [0-2] button "Sign In"
```

Click using: `browse click @0-2`

Refs become stale when the page changes — run `browse snapshot` again to get fresh refs.

## Troubleshooting

- **"No active page"**: Run `browse open <url>`. If persists: `browse stop` then retry.
- **Element ref not found**: Page changed since last snapshot. Run `browse snapshot` again.
- **Timeout errors**: Try `browse open <url> --wait networkidle` for JS-heavy pages.
- **Daemon unresponsive**: `browse stop --force`, then retry.
