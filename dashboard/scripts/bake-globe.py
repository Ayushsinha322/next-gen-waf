# Bake the GeoIP globe's dotted-land dataset (dashboard/lib/globeData.ts) from Natural Earth
# 1:10m Admin 0 Countries, India point of view. Public-domain data; needs numpy + matplotlib.
#
#   curl -LO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_0_countries_ind.geojson
#   python3 -I dashboard/scripts/bake-globe.py ne_10m_admin_0_countries_ind.geojson dashboard/lib/globeData.ts 1.5
#
# Runs offline once; the console never fetches map data at runtime (air-gapped installs).
import json, math, sys
import numpy as np
from matplotlib.path import Path

src, out, step = sys.argv[1], sys.argv[2], float(sys.argv[3])
feats = json.load(open(src))['features']

def polys(geom):
    if geom['type'] == 'Polygon': return [geom['coordinates']]
    if geom['type'] == 'MultiPolygon': return geom['coordinates']
    return []

def ring_area(r):
    a = 0.0
    for (x1, y1), (x2, y2) in zip(r, r[1:] + r[:1]): a += x1 * y2 - x2 * y1
    return abs(a) / 2

# grid
rows = []  # list of (lat, n)
nrows = int(round(180 / step))
pts = []
for i in range(nrows):
    lat = -90 + (i + 0.5) * step
    n = max(1, int(round(360 * math.cos(math.radians(lat)) / step)))
    rows.append((lat, n))
    for j in range(n):
        pts.append((-180 + (j + 0.5) * 360 / n, lat))
pts = np.array(pts)
owner = np.full(len(pts), -1, dtype=np.int32)

codes = []          # index -> code ("" = land with no ISO code)
code_idx = {}
labels = {}         # code -> (area, lat, lon)
for f in feats:
    p = f['properties']
    code = p.get('ISO_A2_EH') or ''
    if code == '-99': code = ''
    if code not in code_idx:
        code_idx[code] = len(codes); codes.append(code)
    ci = code_idx[code]
    area = 0.0
    for poly in polys(f['geometry']):
        outer = poly[0]
        area += ring_area(outer)
        xs = [c[0] for c in outer]; ys = [c[1] for c in outer]
        m = (pts[:, 0] >= min(xs)) & (pts[:, 0] <= max(xs)) & (pts[:, 1] >= min(ys)) & (pts[:, 1] <= max(ys))
        idx = np.nonzero(m)[0]
        if len(idx) == 0: continue
        inside = Path(outer).contains_points(pts[idx])
        for hole in poly[1:]:
            inside &= ~Path(hole).contains_points(pts[idx])
        owner[idx[inside]] = ci
    if code and (code not in labels or area > labels[code][0]):
        labels[code] = (area, round(p['LABEL_Y'], 2), round(p['LABEL_X'], 2))

# runs per row: [start, len, codeIdx, ...]
out_rows = []
k = 0
dots = 0
for lat, n in rows:
    o = owner[k:k + n]; k += n
    r = []
    j = 0
    while j < n:
        if o[j] < 0: j += 1; continue
        s = j
        while j < n and o[j] == o[s]: j += 1
        r += [s, j - s, int(o[s])]
        dots += j - s
    out_rows.append(r)

used = sorted(set(int(x) for x in owner if x >= 0))
print(f'step {step}: {len(pts)} grid points, {dots} land dots, {sum(len(r)//3 for r in out_rows)} runs, {len(codes)} codes, {len(labels)} labels', file=sys.stderr)

with open(out, 'w') as fh:
    fh.write('''/**
 * GENERATED — do not edit by hand. Dotted-globe dataset for the GeoIP globe.
 *
 * Source: Natural Earth 1:10m Admin 0 Countries, India point of view
 * (ne_10m_admin_0_countries_ind), naturalearthdata.com. Natural Earth is in the
 * public domain; no permission or attribution is required. The India point of
 * view is used on purpose: the console is sold in India, and a country highlight
 * that drew a disputed boundary the other way would be a real problem for a
 * customer, not a cosmetic one.
 *
 * Shape: the sphere is cut into latitude bands of GLOBE_STEP degrees, south to
 * north. Band i sits at latitude -90 + (i + 0.5) * step and holds
 * GLOBE_ROW_N[i] evenly spaced dots (about 360 * cos(lat) / step, so every dot
 * covers about the same area; stored, not recomputed, because Python and
 * JavaScript round halves differently). GLOBE_ROWS[i] lists that band's land dots as runs of
 * [first dot, count, index into GLOBE_CODES]. Code "" is land with no ISO code.
 * GLOBE_LABELS is each country's label point, [lat, lon], from LABEL_Y/LABEL_X.
 *
 * Regenerate with dashboard/scripts/bake-globe.py (step %s); its header has the commands.
 */
''' % step)
    fh.write(f'export const GLOBE_STEP = {step};\n')
    fh.write('export const GLOBE_ROW_N: readonly number[] = ' + json.dumps([n for _, n in rows], separators=(',', ':')) + ';\n')
    fh.write('export const GLOBE_CODES: readonly string[] = ' + json.dumps(codes, separators=(',', ':')) + ';\n')
    fh.write('export const GLOBE_ROWS: readonly (readonly number[])[] = [\n')
    for r in out_rows: fh.write(json.dumps(r, separators=(',', ':')) + ',\n')
    fh.write('];\n')
    fh.write('export const GLOBE_LABELS: Readonly<Record<string, readonly [number, number]>> = {\n')
    items = sorted(labels.items())
    for i in range(0, len(items), 6):
        fh.write('  ' + ' '.join(f'{c}:[{la},{lo}],' for c, (_, la, lo) in items[i:i+6]) + '\n')
    fh.write('};\n')
