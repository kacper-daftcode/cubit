//! Independent NVIDIA SM120 sweeps, including the QMMA control that exposed
//! reserved OPEX emission during ordinary-SASS kernel authoring. No GPU needed.
use cubit::{encoder::encode_instruction, ir::ControlCode, IsaTable};
use serde::Deserialize;
use std::{path::Path, sync::OnceLock};

#[derive(Deserialize)]
struct Sweep {
    family: String,
    pc: u32,
    control: String,
    body: String,
    full128: String,
    nvidia_accepted: bool,
}

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Sweep>,
}

fn table(sm: u32) -> &'static IsaTable {
    static SM120: OnceLock<IsaTable> = OnceLock::new();
    static SM103: OnceLock<IsaTable> = OnceLock::new();
    match sm {
        120 => SM120.get_or_init(|| IsaTable::load(Path::new("tables/sm120.json")).unwrap()),
        103 => SM103.get_or_init(|| IsaTable::load(Path::new("tables/sm103a.json")).unwrap()),
        _ => unreachable!(),
    }
}

#[test]
fn independent_nvidia_sweeps_keep_162_legal_words_exact_and_refuse_30_reserved() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/sm120_control_opex.json")).unwrap();
    assert_eq!(fixture.cases.len(), 192);
    let (mut accepted, mut rejected) = (0, 0);
    for case in fixture.cases {
        let text = format!("[{}] {} ;", case.control, case.body);
        let insn = cubit::parse_cuasm_line(&text, case.pc).unwrap();
        let before = insn.ctrl;
        let actual = encode_instruction(&insn, table(120));
        if case.nvidia_accepted {
            assert_eq!(
                actual.unwrap(),
                u128::from_str_radix(&case.full128, 16).unwrap(),
                "{} at 0x{:x}: {text}",
                case.family,
                case.pc
            );
            accepted += 1;
        } else {
            assert!(
                actual
                    .unwrap_err()
                    .to_string()
                    .contains("reserved scheduling control"),
                "{text}"
            );
            rejected += 1;
        }
        assert_eq!(
            insn.ctrl, before,
            "encoding must not normalize author controls"
        );
    }
    assert_eq!((accepted, rejected), (162, 30));
}

#[test]
fn strict_source_refuses_reserved_qmma_controls_and_retains_legal_s15() {
    use cubit::roundtrip_audit::encode_semantic_source;
    let body = "QMMA.16832.F32.E4M3.E4M3 R80, R80, R48, RZ";
    for stall in [0, 12, 13, 14, 15] {
        let source = format!(".entry kernel\n[B------:R-:W-:Y:S{stall:02}] {body} ;\n.endentry\n");
        let error = encode_semantic_source(&source, table(120)).unwrap_err();
        assert!(format!("{error:#}").contains("reserved scheduling control"));
    }
    let source = format!(".entry kernel\n[B------:R-:W-:-:S15] {body} ;\n.endentry\n");
    let actual = encode_semantic_source(&source, table(120)).unwrap();
    // Independent NVIDIA sweep's no-yield S15 word, complete 128 bits.
    assert_eq!(actual, 0x000fde0000002cff000000305050727au128.to_le_bytes());
}

#[test]
fn typed_stall_cannot_overflow_into_yield_or_scoreboard_bits() {
    for stall in [16, 17, 31, 32, 99, 255] {
        let mut insn = cubit::parse_sass("NOP ;", 0).unwrap();
        insn.ctrl.stall = stall;
        let error = encode_instruction(&insn, table(120)).unwrap_err();
        assert!(error.to_string().contains("four-bit field"), "{error:#}");
    }
}

#[test]
fn generated_postpass_repairs_only_yield_and_never_shortens_a_delay() {
    for yield_flag in [false, true] {
        for stall in 0..=15 {
            let before = ControlCode {
                stall,
                yield_flag,
                write_bar: 4,
                read_bar: 2,
                wait_mask: 0b101101,
            };
            let mut insn = cubit::parse_sass("NOP ;", 0).unwrap();
            insn.ctrl = before;
            cubit::scheduling_pass::legalize_generated_sm120_controls(std::slice::from_mut(
                &mut insn,
            ));
            assert_eq!(
                (
                    insn.ctrl.stall,
                    insn.ctrl.write_bar,
                    insn.ctrl.read_bar,
                    insn.ctrl.wait_mask
                ),
                (
                    before.stall,
                    before.write_bar,
                    before.read_bar,
                    before.wait_mask
                )
            );
            let actual = ((insn.ctrl.yield_flag as u8) << 4) | insn.ctrl.stall;
            assert!(matches!(actual, 0x00..=0x0f | 0x11..=0x1b));
            if matches!(((yield_flag as u8) << 4) | stall, 0x00..=0x0f | 0x11..=0x1b) {
                assert_eq!(insn.ctrl, before);
            }
        }
    }
}

#[test]
fn generated_uniform_predicate_schedule_keeps_its_s14_delay_without_reserved_yield() {
    // Before this guard the ordinary legacy schedule emits Y+S14 for UISETP.
    let mut insns = vec![
        cubit::parse_sass("UISETP.EQ.AND UP0, UPT, UR15, 0xc, UPT ;", 0).unwrap(),
        cubit::parse_sass("EXIT ;", 16).unwrap(),
    ];
    cubit::scheduling_pass::schedule(&mut insns, Some(table(120)));
    assert_eq!(
        insns[0].ctrl,
        ControlCode {
            stall: 14,
            yield_flag: false,
            write_bar: 7,
            read_bar: 7,
            wait_mask: 0,
        }
    );
    let word = encode_instruction(&insns[0], table(120)).unwrap();
    assert_eq!((word >> 105) & 0x1f, 0x0e);
}

#[test]
fn explicit_controls_stay_untouched_until_the_encoder_rejects_them() {
    let mut frozen = cubit::parse_cuasm_line("[B0-2--5:R1:W4:Y:S15] NOP ;", 0).unwrap();
    let before = frozen.ctrl;
    cubit::scheduling_pass::legalize_generated_sm120_controls(std::slice::from_mut(&mut frozen));
    assert_eq!(frozen.ctrl, before);
    for hand_sched in [false, true] {
        let mut insn = frozen.clone();
        insn.hand_sched = hand_sched;
        cubit::scheduling_pass::schedule(std::slice::from_mut(&mut insn), Some(table(120)));
        assert_eq!(
            insn.ctrl, before,
            "explicit direct-IR control is also author-owned"
        );
        assert!(encode_instruction(&insn, table(120)).is_err());
    }
}

#[test]
fn other_architectures_keep_their_existing_encoding_contract() {
    // This is a compatibility check, not a claim of NVIDIA legality on SM103a.
    for stall in [0, 12, 13, 14, 15] {
        let text = format!("[B------:R-:W-:Y:S{stall:02}] NOP ;");
        let insn = cubit::parse_cuasm_line(&text, 0).unwrap();
        let word = encode_instruction(&insn, table(103)).unwrap();
        assert_eq!((word >> 105) & 0x1f, 16 + stall as u128);
    }
}
