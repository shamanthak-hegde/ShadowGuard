import React, { useRef, useEffect } from 'react';
import * as d3 from 'd3';

export default function TrafficTimeline({ events }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);

  useEffect(() => {
    if (!events || events.length === 0 || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth;
    const height = 220;
    const margin = { top: 20, right: 20, bottom: 30, left: 40 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    // Bucket events into 5-minute intervals
    const now = new Date();
    const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const bucketSize = 5 * 60 * 1000; // 5 minutes

    const buckets = new Map();
    for (let t = twoHoursAgo.getTime(); t <= now.getTime(); t += bucketSize) {
      buckets.set(t, { time: new Date(t), clean: 0, redacted: 0, blocked: 0 });
    }

    events.forEach((e) => {
      const t = new Date(e.timestamp).getTime();
      const bucketKey = Math.floor((t - twoHoursAgo.getTime()) / bucketSize) * bucketSize + twoHoursAgo.getTime();
      const bucket = buckets.get(bucketKey);
      if (bucket) {
        if (e.action === 'redacted') bucket.redacted++;
        else if (e.action === 'blocked') bucket.blocked++;
        else bucket.clean++;
      }
    });

    const data = Array.from(buckets.values());

    // Clear previous
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3
      .select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('class', 'd3-chart');

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Scales
    const x = d3
      .scaleTime()
      .domain([twoHoursAgo, now])
      .range([0, innerW]);

    const maxY = d3.max(data, (d) => d.clean + d.redacted + d.blocked) || 5;
    const y = d3
      .scaleLinear()
      .domain([0, maxY * 1.2])
      .range([innerH, 0]);

    // Grid lines
    g.append('g')
      .attr('class', 'grid')
      .call(
        d3.axisLeft(y).ticks(5).tickSize(-innerW).tickFormat('')
      )
      .selectAll('line')
      .attr('stroke', 'rgba(0, 240, 255, 0.06)');

    g.selectAll('.grid .domain').remove();

    // Stacked areas
    const stack = d3
      .stack()
      .keys(['clean', 'redacted', 'blocked'])
      .order(d3.stackOrderNone)
      .offset(d3.stackOffsetNone);

    const series = stack(data);

    const colors = {
      clean: '#00f0ff',
      redacted: '#ff8800',
      blocked: '#ff0040',
    };

    const opacities = {
      clean: 0.15,
      redacted: 0.3,
      blocked: 0.4,
    };

    // Create gradient defs
    const defs = svg.append('defs');
    Object.entries(colors).forEach(([key, color]) => {
      const grad = defs
        .append('linearGradient')
        .attr('id', `grad-${key}`)
        .attr('x1', '0%')
        .attr('y1', '0%')
        .attr('x2', '0%')
        .attr('y2', '100%');

      grad
        .append('stop')
        .attr('offset', '0%')
        .attr('stop-color', color)
        .attr('stop-opacity', opacities[key]);

      grad
        .append('stop')
        .attr('offset', '100%')
        .attr('stop-color', color)
        .attr('stop-opacity', 0.02);
    });

    const area = d3
      .area()
      .x((d) => x(d.data.time))
      .y0((d) => y(d[0]))
      .y1((d) => y(d[1]))
      .curve(d3.curveMonotoneX);

    g.selectAll('.area')
      .data(series)
      .join('path')
      .attr('class', 'area')
      .attr('d', area)
      .attr('fill', (d) => `url(#grad-${d.key})`)
      .attr('stroke', (d) => colors[d.key])
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.6);

    // Axes
    g.append('g')
      .attr('transform', `translate(0,${innerH})`)
      .call(
        d3
          .axisBottom(x)
          .ticks(6)
          .tickFormat(d3.timeFormat('%H:%M'))
      )
      .selectAll('text')
      .attr('fill', '#6b7280')
      .attr('font-size', '10px');

    g.append('g')
      .call(d3.axisLeft(y).ticks(5))
      .selectAll('text')
      .attr('fill', '#6b7280')
      .attr('font-size', '10px');

    // Tooltip
    const tooltip = d3
      .select(container)
      .selectAll('.d3-tooltip')
      .data([0])
      .join('div')
      .attr('class', 'd3-tooltip')
      .style('opacity', 0);

    const bisect = d3.bisector((d) => d.time).left;

    const overlay = g
      .append('rect')
      .attr('width', innerW)
      .attr('height', innerH)
      .attr('fill', 'none')
      .attr('pointer-events', 'all');

    overlay.on('mousemove', (event) => {
      const [mx] = d3.pointer(event);
      const date = x.invert(mx);
      const i = bisect(data, date, 1);
      const d = data[Math.min(i, data.length - 1)];
      if (!d) return;

      tooltip
        .style('opacity', 1)
        .style('left', `${event.offsetX + 15}px`)
        .style('top', `${event.offsetY - 10}px`)
        .html(
          `<div style="color:#00f0ff">${d3.timeFormat('%H:%M')(d.time)}</div>` +
          `<div>Clean: ${d.clean}</div>` +
          `<div style="color:#ff8800">Redacted: ${d.redacted}</div>` +
          `<div style="color:#ff0040">Blocked: ${d.blocked}</div>`
        );
    });

    overlay.on('mouseleave', () => {
      tooltip.style('opacity', 0);
    });
  }, [events]);

  return (
    <div className="glass-panel p-4">
      <h3 className="text-xs font-semibold text-gray-400 tracking-widest uppercase mb-3">
        Traffic Timeline
      </h3>
      <div ref={containerRef} className="relative">
        <svg ref={svgRef} />
      </div>
    </div>
  );
}
