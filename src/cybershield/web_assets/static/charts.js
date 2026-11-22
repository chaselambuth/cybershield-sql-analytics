"use strict";
// Charts use the displayed query rows only; no regrouping, prediction or API calls.
(function (scope) {
  function numeric(value) {
    if (typeof value === "string" && !/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(value)) return null;
    if (typeof value !== "string" && typeof value !== "number") return null;
    const n = Number(value);
    if (!Number.isFinite(n) || Math.abs(n) > Number.MAX_SAFE_INTEGER) return null;
    return n;
  }
  function numericColumns(result) {
    return result.columns.map((_, i) => i).filter(i => result.rows.some(row => numeric(row[i]) !== null));
  }
  function series(result, x, y, type) {
    const limit = type === "bar" ? 30 : 100;
    const valid = result.rows.flatMap((row, index) => {
      const value = numeric(row[y]);
      return value === null ? [] : [{label: row[x] === null ? "(missing)" : String(row[x]), value,
        ...(type === "line" ? {index} : {})}];
    });
    return {points: valid.slice(0, limit), omitted: result.rows.length - valid.length,
      hidden: Math.max(0, valid.length - limit), total: result.rows.length,
      slots: type === "line" && valid.length > limit ? valid[limit - 1].index + 1 : result.rows.length};
  }
  function svgNode(tag, attrs = {}, text) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function render(container, result, {x, y, type, title}) {
    container.replaceChildren();
    const data = series(result, x, y, type);
    if (!data.points.length) return {...data, empty: true};
    const bar = type === "bar";
    const width = 900, height = bar ? Math.max(240, data.points.length * 31 + 58) : 330;
    const left = bar ? 185 : 74, right = 42, top = 22, bottom = 64;
    const plotW = width - left - right, plotH = height - top - bottom;
    const low = Math.min(0, ...data.points.map(p => p.value));
    const high = Math.max(0, ...data.points.map(p => p.value));
    const span = high - low || 1;
    const compact = n => new Intl.NumberFormat("en-US", {maximumSignificantDigits: 4, notation: Math.abs(n) >= 1e6 ? "compact" : "standard"}).format(n);
    const svg = svgNode("svg", {viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${title}. ${result.columns[y]} by ${result.columns[x]}. ${data.points.length} rows in query order.`});
    svg.append(svgNode("title", {}, title));
    for (let i = 0; i <= 4; i++) {
      const value = low + span * i / 4;
      if (bar) {
        const px = left + plotW * i / 4;
        svg.append(svgNode("line", {x1: px, x2: px, y1: top, y2: height - bottom, class: "chart-grid"}));
        svg.append(svgNode("text", {x: px, y: height - bottom + 23, "text-anchor": "middle", class: "chart-tick"}, compact(value)));
      } else {
        const py = height - bottom - plotH * i / 4;
        svg.append(svgNode("line", {x1: left, x2: width - right, y1: py, y2: py, class: "chart-grid"}));
        svg.append(svgNode("text", {x: left - 12, y: py + 4, "text-anchor": "end", class: "chart-tick"}, compact(value)));
      }
    }
    if (bar) {
      const scale = value => left + (value - low) / span * plotW;
      const zero = scale(0), rowH = plotH / data.points.length;
      svg.append(svgNode("line", {x1: zero, x2: zero, y1: top, y2: height - bottom, class: "chart-baseline"}));
      data.points.forEach((p, i) => {
        const yPos = top + rowH * i + rowH * .16;
        const label = svgNode("text", {x: left - 14, y: yPos + rowH * .45, "text-anchor": "end", class: "chart-label"}, p.label.length > 23 ? p.label.slice(0, 22) + "…" : p.label);
        label.append(svgNode("title", {}, p.label));
        const rect = svgNode("rect", {x: Math.min(zero, scale(p.value)), y: yPos,
          width: Math.max(1, Math.abs(scale(p.value) - zero)), height: Math.max(3, rowH * .65), rx: 3, class: "chart-bar", tabindex: 0});
        rect.append(svgNode("title", {}, `${p.label}: ${p.value}`));
        svg.append(label, rect);
      });
    } else {
      const point = p => [left + (data.slots === 1 ? .5 : p.index / (data.slots - 1)) * plotW,
        height - bottom - (p.value - low) / span * plotH];
      let segment = [];
      const appendSegment = () => {
        if (segment.length > 1) svg.append(svgNode("polyline", {points: segment.map(p => point(p).join(",")).join(" "), class: "chart-line"}));
      };
      data.points.forEach(p => {
        if (segment.length && p.index !== segment[segment.length - 1].index + 1) {appendSegment(); segment = [];}
        segment.push(p);
      });
      appendSegment();
      data.points.forEach((p, i) => {
        const [px, py] = point(p);
        const dot = svgNode("circle", {cx: px, cy: py, r: 4, class: "chart-point", tabindex: 0});
        dot.append(svgNode("title", {}, `${p.label}: ${p.value}`)); svg.append(dot);
        if (i % Math.max(1, Math.ceil(data.points.length / 5)) === 0 || i === data.points.length - 1) {
          svg.append(svgNode("text", {x: px, y: height - bottom + 24, "text-anchor": "middle", class: "chart-tick"}, p.label.length > 16 ? p.label.slice(0, 16) : p.label));
        }
      });
    }
    svg.append(svgNode("text", {x: left + plotW / 2, y: height - 12, "text-anchor": "middle", class: "chart-axis"}, bar ? result.columns[y] : result.columns[x]));
    container.append(svg);
    return data;
  }
  const api = {numeric, numericColumns, series, render};
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else scope.CyberShieldCharts = api;
})(typeof window === "undefined" ? globalThis : window);
