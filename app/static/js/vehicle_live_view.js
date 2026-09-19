// The view of one vehicle, derived from its live payload — the shape
// `build_vehicle_live_payload()` produces, embedded in the dashboard card, rendered
// into the vehicle page and pushed over the `vehicle:<id>` socket.
//
// One derivation for the two pages that show it (the dashboard's cards and the
// vehicle page's overview), so a rule — "0 is unknown in a V2 frame", "V3 before V2",
// "the charge line is hidden once the charge is complete" — is written once. Every
// value comes back as a precomputed field, because Alpine's CSP build evaluates no
// expressions: a template binds `x-text="socText"`, never `x-text="soc + '%'"`.
//
//   const view = window.ovmsLiveView.create({ lang, imperial, labels });
//   Object.assign(component, view.derive(payload));
//
// A metric the vehicle does not report is not shown: every optional field has a
// `show*` flag beside its text.
(() => {
    'use strict';

    const MI_TO_KM = 1.609344;
    const KM_TO_MI = 1 / MI_TO_KM;
    const BAR_TO_PSI = 14.503774;
    // V3 carries the raw v.c.state ("topoff", "prepare"); the V2 parser hands out its
    // display words ("Topping Off", "Preparing"). One key each.
    const STATE_ALIASES = { 'toppingoff': 'topoff', 'preparing': 'prepare' };

    const num = (v) => { if (v === null || v === undefined || v === '') return null; const n = Number.parseFloat(v); return Number.isFinite(n) ? n : null; };
    const yes = (v) => v === true || v === 1 || /^(yes|true|1|on)$/i.test(String(v ?? ''));
    const text = (v) => { if (v === null || v === undefined) return ''; const s = String(v).trim(); return /^(n\/a|none|null)$/i.test(s) ? '' : s; };
    // The first defined value wins; V3 (live metrics) before V2 (last stored frame).
    const first = (...values) => { for (const v of values) { const n = num(v); if (n !== null) return n; } return null; };
    const flag = (...values) => { for (const v of values) { if (v !== null && v !== undefined && v !== '') return yes(v); } return null; };
    const firstText = (...values) => { for (const v of values) { const s = text(v); if (s !== '') return s; } return ''; };

    function create(config) {
        const L = config.labels || {};
        const LANG = config.lang || 'en';
        const imperial = !!config.imperial;
        const rtf = (typeof Intl !== 'undefined' && Intl.RelativeTimeFormat) ? new Intl.RelativeTimeFormat(LANG, { numeric: 'auto' }) : null;

        const fmt = (n, digits) => n.toLocaleString(LANG, { minimumFractionDigits: digits, maximumFractionDigits: digits });

        function toKm(value, units) {
            const n = num(value);
            if (n === null) return null;
            const u = String(units || '').toUpperCase();
            return (u !== '' && u !== 'N/A' && u !== 'K') ? n * MI_TO_KM : n;
        }
        function distance(km, digits) {
            if (km === null) return L.na || '';
            return imperial ? `${fmt(km * KM_TO_MI, digits)} mi` : `${fmt(km, digits)} km`;
        }
        function minutes(total) {
            if (total === null || total < 0) return null;
            const h = Math.floor(total / 60), m = Math.round(total % 60);
            return h > 0 ? `${h}h ${String(m).padStart(2, '0')}m` : `${m}m`;
        }
        function relative(iso) {
            if (!iso) return { text: L.never || '', title: '' };
            const then = new Date(iso);
            if (Number.isNaN(then.getTime())) return { text: L.never || '', title: '' };
            const title = then.toLocaleString(LANG);
            const seconds = Math.round((then.getTime() - Date.now()) / 1000);
            if (!rtf) return { text: title, title };
            const abs = Math.abs(seconds);
            if (abs < 45) return { text: L.justNow || title, title };
            if (abs < 3600) return { text: rtf.format(Math.round(seconds / 60), 'minute'), title };
            if (abs < 86400) return { text: rtf.format(Math.round(seconds / 3600), 'hour'), title };
            return { text: rtf.format(Math.round(seconds / 86400), 'day'), title };
        }
        // Every temperature the vehicle reports is Celsius; the profile's unit
        // preference decides how it reads, here and nowhere else.
        function temperature(value) {
            const n = num(value);
            if (n === null) return null;
            return imperial ? `${fmt(n * 9 / 5 + 32, 1)} °F` : `${fmt(n, 1)} °C`;
        }
        // Tyre pressure arrives in bar; the same preference picks psi.
        function pressure(value) {
            const n = num(value);
            if (n === null) return null;
            return imperial ? `${fmt(n * BAR_TO_PSI, 1)} psi` : `${fmt(n, 2)} bar`;
        }

        function derive(p) {
            const out = {};
            if (!p || typeof p !== 'object') return out;
            const v3 = p.v3_metrics || {};
            const v2 = p.v2_metrics || {};

            // online state
            const online = !!p.isV2Online || !!p.isV3Online;
            const via = (p.isV2Online && p.isV3Online) ? 'V2+V3' : p.isV2Online ? 'V2' : p.isV3Online ? 'V3' : '';
            out.online = online;
            out.statusText = online ? `${L.online} (${via})` : L.offline;
            out.statusPillClass = online
                ? 'text-green-300 bg-green-700/60 border-green-500/50'
                : 'text-red-300 bg-red-700/60 border-red-500/50';
            out.statusDotClass = online ? 'bg-green-400 animate-pulse' : 'bg-red-400';

            // state of charge. Offline, the number and the bar are grey: the value is
            // the last one heard, not the battery now, and a green 80 % on a module
            // that went quiet a week ago read as current. The width stays — the last
            // known level is still information; only the colour claims freshness.
            const soc = num(p.soc);
            out.socText = soc === null ? '–' : `${fmt(soc, 0)}%`;
            out.socClass = (soc === null || !online) ? 'text-text-secondary'
                : soc >= 70 ? 'text-green-400' : soc >= 30 ? 'text-yellow-400' : 'text-red-400';
            const pct = soc === null ? 0 : Math.max(0, Math.min(100, soc));
            out.barStyle = { width: `${pct}%` };

            // charging
            const rawState = String(p.charge_state_text || '').trim().toLowerCase().replace(/\s+/g, '');
            const state = STATE_ALIASES[rawState] || rawState;
            const chargingFlag = flag(v3['v.c.charging'], v2['environment.charging']);
            const charging = chargingFlag !== null ? chargingFlag : (state === 'charging' || state === 'topoff');
            out.isCharging = charging;
            const gradient = (soc === null || !online) ? 'bg-gray-600'
                : soc >= 70 ? 'bg-gradient-to-r from-green-600 to-green-400'
                : soc >= 30 ? 'bg-gradient-to-r from-yellow-600 to-yellow-400'
                : 'bg-gradient-to-r from-red-600 to-orange-400';
            // No sweep on a grey bar: the animation says "happening now", and offline
            // nothing is.
            out.barClass = (charging && online) ? `${gradient} ovms-charging` : gradient;

            const lineV = num(p.line_voltage), lineA = num(p.charge_current);
            const kw = first(v3['v.c.power'], v2['status.charge_power_input_kw'],
                             (lineV !== null && lineA !== null) ? (lineV * lineA) / 1000 : null);
            out.chargePowerText = kw === null ? '' : `${fmt(kw, 1)} kW`;
            const kwh = first(v3['v.c.kwh'], v2['status.energy_sum_running_charge_kwh']);
            out.showChargeEnergy = kwh !== null && kwh > 0;
            out.chargeEnergyText = kwh === null ? '' : `${fmt(kwh, 1)} kWh`;
            const limit = first(v3['v.c.limit.soc'], v2['status.acc_soc_limit']);
            const toLimit = first(v3['v.c.duration.soc'], v2['status.acc_mins_to_limit']);
            const toFull = first(v3['v.c.duration.full'], v2['status.acc_mins_to_full'], v2['status.charge_duration_minutes']);
            let eta = '';
            if (limit !== null && limit > 0 && limit < 100 && minutes(toLimit) !== null) eta = `${fmt(limit, 0)}%: ${minutes(toLimit)}`;
            else if (minutes(toFull) !== null) eta = `${L.toFull || '100%'}: ${minutes(toFull)}`;
            out.chargeEtaText = eta;

            // The state word, for a tile that always names it; and the line under the
            // bar, which only says something worth a glance — a completed charge is
            // what the full green bar already shows, so that one is silent.
            const stateKnown = state !== '' && state !== 'n/a';
            const chargeStates = L.chargeStates || {};
            out.chargeStateText = (stateKnown && Object.hasOwn(chargeStates, state) ? chargeStates[state] : '') || text(p.charge_state_text);
            out.chargeStateClass = state === 'done' ? 'text-green-400' : state === 'stopped' ? 'text-amber-300' : charging ? 'text-green-400' : 'text-text-secondary';
            out.showChargeStateTile = stateKnown;
            out.showChargeState = !charging && stateKnown && state !== 'done';
            out.chargeModeText = firstText(v3['v.c.mode'], p.charge_mode_text);
            out.showChargeMode = out.chargeModeText !== '';

            // range & temperatures
            const rangeKm = toKm(p.estimated_range, p.units);
            out.showRange = rangeKm !== null;
            out.rangeText = distance(rangeKm, 0);
            const bTemp = first(v3['v.b.temp'], v2['environment.temp_battery_c']);
            out.showBatteryTemp = bTemp !== null;
            out.batteryTempText = bTemp === null ? '' : temperature(bTemp);
            const aTemp = first(v3['v.e.temp'], v2['environment.temp_ambient_c']);
            out.showAmbientTemp = aTemp !== null;
            out.ambientTempText = aTemp === null ? '' : temperature(aTemp);
            const mTemp = first(v3['v.m.temp'], v2['environment.temp_motor_c']);
            out.showMotorTemp = mTemp !== null && mTemp !== 0;
            out.motorTempText = mTemp === null ? '' : temperature(mTemp);
            const cTemp = first(v3['v.e.cabintemp'], v2['environment.temp_cabin_c']);
            out.showCabinTemp = cTemp !== null && cTemp !== 0;
            out.cabinTempText = cTemp === null ? '' : temperature(cTemp);

            // tiles
            // A metric the vehicle does not report is no tile. A V2 frame carries 0
            // in a field it has no reading for (SOH, odometer, 12V, pack voltage), so
            // 0 is unknown there too — no battery is at 0 % health or 0 V and still
            // talking.
            const v12 = num(p.vehicle_12v);
            out.showV12 = v12 !== null && v12 > 0;
            out.v12Text = out.showV12 ? `${fmt(v12, 1)} V` : '';
            out.v12Class = !out.showV12 ? 'text-text-primary' : v12 < 11.8 ? 'text-red-400' : v12 < 12.3 ? 'text-yellow-400' : 'text-text-primary';
            const soh = first(p.battery_soh, v3['v.b.soh'], v2['status.battery_soh_percent']);
            out.showSoh = soh !== null && soh > 0;
            out.sohText = out.showSoh ? `${fmt(soh, 0)}%` : '';
            // V3 publishes the odometer in km; the V2 frame in the vehicle's units, tenths.
            const odoV3 = num(v3['v.p.odometer']);
            const odoV2 = num(v2['environment.odometer_10th_unit']);
            const odoKm = odoV3 !== null ? odoV3 : odoV2 !== null ? toKm(odoV2 / 10, p.units) : null;
            out.showOdometer = odoKm !== null && odoKm > 0;
            out.odometerText = out.showOdometer ? distance(odoKm, 0) : '';
            // the trip meter, same units as the odometer on each protocol
            const tripV3 = num(v3['v.p.trip']);
            const tripV2 = num(v2['environment.trip_meter_10th_unit']);
            const tripKm = tripV3 !== null ? tripV3 : tripV2 !== null ? toKm(tripV2 / 10, p.units) : null;
            out.showTrip = tripKm !== null && tripKm > 0;
            out.tripText = out.showTrip ? distance(tripKm, 1) : '';

            // the pack: voltage and current go together — a vehicle that reports one
            // reports the other, and 0 A idle is a reading while 0 V is not
            const packV = first(v3['v.b.voltage'], p.battery_voltage);
            const packA = first(v3['v.b.current'], p.battery_current);
            out.showBatteryVoltage = packV !== null && packV > 0;
            out.batteryVoltageText = out.showBatteryVoltage ? `${fmt(packV, 1)} V` : '';
            out.showBatteryCurrent = out.showBatteryVoltage && packA !== null;
            out.batteryCurrentText = out.showBatteryCurrent ? `${fmt(packA, 1)} A` : '';
            // the charger side is only a reading while a charger is connected
            const chargerV = first(v3['v.c.voltage'], p.line_voltage);
            const chargerA = first(v3['v.c.current'], p.charge_current);
            out.showLineVoltage = charging && chargerV !== null && chargerV > 0;
            out.lineVoltageText = out.showLineVoltage ? `${fmt(chargerV, 0)} V` : '';
            out.showChargeCurrent = charging && chargerA !== null;
            out.chargeCurrentText = out.showChargeCurrent ? `${fmt(chargerA, 1)} A` : '';

            // position: the payload's lat/lon, or the V3 pair; 0,0 is the sea off Ghana
            const lat = first(p.lat, v3['v.p.latitude']);
            const lon = first(p.lon, v3['v.p.longitude']);
            out.showPosition = lat !== null && lon !== null && !(lat === 0 && lon === 0);
            out.positionText = out.showPosition ? `${lat.toFixed(4)}, ${lon.toFixed(4)}` : '';

            // last seen
            const seen = relative(p.lastMessageAt);
            out.lastSeenText = seen.text;
            out.lastSeenTitle = seen.title;

            // lock & ignition
            const locked = flag(v3['v.e.locked'], v2['environment.car_locked']);
            out.showLocked = locked !== null;
            out.isLocked = locked === true;
            out.isUnlocked = locked === false;
            out.lockTitle = locked === true ? L.locked : L.unlocked;
            out.lockClass = locked === true ? 'text-green-400' : 'text-amber-300';
            out.isOn = flag(v3['v.e.on'], v2['environment.car_on']) === true;
            return out;
        }

        return { derive, relative, distance, temperature, pressure, imperial };
    }

    window.ovmsLiveView = { create };
})();
