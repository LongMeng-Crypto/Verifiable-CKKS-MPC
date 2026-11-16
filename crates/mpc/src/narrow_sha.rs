#[cfg(test)]
use crate::arithmetic::F;
#[cfg(test)]
use p3_air::AirLayout;
#[cfg(test)]
use p3_air::symbolic::get_symbolic_constraints;
#[cfg(test)]
use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
#[cfg(test)]
use p3_field::Algebra;
#[cfg(test)]
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_sha256_air::NUM_SHA256_COLS;
#[cfg(test)]
use p3_sha256_air::Sha256Air;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(crate) enum Node {
    Input(usize),
    Parameter(usize),
    Constant(u64),
    Add(usize, usize),
    Sub(usize, usize),
    Mul(usize, usize),
    Neg(usize),
}
#[cfg(test)]
#[derive(Default)]
struct Graph {
    nodes: Vec<Node>,
    intern: HashMap<Node, usize>,
    pointers: HashMap<usize, usize>,
}
#[cfg(test)]
impl Graph {
    /// Interns and simplifies a SHA expression node.
    fn node(&mut self, n: Node) -> usize {
        let n = match n {
            Node::Add(x, y) if self.nodes[x] == Node::Constant(0) => return y,
            Node::Add(x, y) | Node::Sub(x, y) if self.nodes[y] == Node::Constant(0) => return x,
            Node::Mul(x, y)
                if self.nodes[x] == Node::Constant(0) || self.nodes[y] == Node::Constant(0) =>
            {
                Node::Constant(0)
            }
            Node::Mul(x, y) if self.nodes[x] == Node::Constant(1) => return y,
            Node::Mul(x, y) if self.nodes[y] == Node::Constant(1) => return x,
            Node::Add(x, y) | Node::Sub(x, y) | Node::Mul(x, y)
                if matches!(self.nodes[x], Node::Constant(_))
                    && matches!(self.nodes[y], Node::Constant(_)) =>
            {
                let Node::Constant(a) = self.nodes[x] else {
                    unreachable!()
                };
                let Node::Constant(b) = self.nodes[y] else {
                    unreachable!()
                };
                Node::Constant(
                    (match n {
                        Node::Add(..) => F::from_u64(a) + F::from_u64(b),
                        Node::Sub(..) => F::from_u64(a) - F::from_u64(b),
                        _ => F::from_u64(a) * F::from_u64(b),
                    })
                    .as_canonical_u64(),
                )
            }
            Node::Neg(x) if matches!(self.nodes[x], Node::Constant(_)) => {
                let Node::Constant(c) = self.nodes[x] else {
                    unreachable!()
                };
                Node::Constant((-F::from_u64(c)).as_canonical_u64())
            }
            n => n,
        };
        if let Some(i) = self.intern.get(&n) {
            *i
        } else {
            let i = self.nodes.len();
            self.nodes.push(n.clone());
            self.intern.insert(n, i);
            i
        }
    }
    #[cfg(test)]
    /// Captures an official symbolic SHA constraint.
    fn capture(&mut self, e: &SymbolicExpression<F>) -> usize {
        self.capture_public(e, &[])
    }
    /// Captures a SHA expression with public constants substituted.
    fn capture_public(&mut self, e: &SymbolicExpression<F>, prep: &[F]) -> usize {
        let ptr = e as *const _ as usize;
        if let Some(i) = self.pointers.get(&ptr) {
            return *i;
        }
        let n = match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset: 0 } => Node::Input(v.index),
                BaseEntry::Preprocessed { offset: 0 } => {
                    Node::Constant(prep[v.index].as_canonical_u64())
                }
                _ => panic!("unsupported SHA variable"),
            },
            SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => Node::Constant(c.as_canonical_u64()),
            SymbolicExpr::Add { x, y, .. } => {
                Node::Add(self.capture_public(x, prep), self.capture_public(y, prep))
            }
            SymbolicExpr::Sub { x, y, .. } => {
                Node::Sub(self.capture_public(x, prep), self.capture_public(y, prep))
            }
            SymbolicExpr::Mul { x, y, .. } => {
                Node::Mul(self.capture_public(x, prep), self.capture_public(y, prep))
            }
            SymbolicExpr::Neg { x, .. } => Node::Neg(self.capture_public(x, prep)),
            _ => panic!("unsupported official SHA expression"),
        };
        let i = self.node(n);
        self.pointers.insert(ptr, i);
        i
    }
    /// Normalizes expression inputs and coefficient parameters.
    fn normalize(&self, root: usize) -> (Vec<Node>, Vec<usize>, Vec<u64>) {
        /// Rebuilds a normalized SHA expression node.
        fn visit(
            g: &Graph,
            i: usize,
            out: &mut Graph,
            vars: &mut Vec<usize>,
            params: &mut Vec<u64>,
            memo: &mut HashMap<usize, usize>,
        ) -> usize {
            if let Some(j) = memo.get(&i) {
                return *j;
            }
            let n = match g.nodes[i] {
                Node::Input(v) => {
                    let j = vars.iter().position(|x| *x == v).unwrap_or_else(|| {
                        vars.push(v);
                        vars.len() - 1
                    });
                    Node::Input(j)
                }
                Node::Constant(c) => {
                    if c == 0 || c.is_power_of_two() || (crate::arithmetic::Q - c).is_power_of_two()
                    {
                        Node::Constant(c)
                    } else {
                        let j = params.iter().position(|x| *x == c).unwrap_or_else(|| {
                            params.push(c);
                            params.len() - 1
                        });
                        Node::Parameter(j)
                    }
                }
                Node::Parameter(_) => unreachable!(),
                Node::Add(x, y) => Node::Add(
                    visit(g, x, out, vars, params, memo),
                    visit(g, y, out, vars, params, memo),
                ),
                Node::Sub(x, y) => Node::Sub(
                    visit(g, x, out, vars, params, memo),
                    visit(g, y, out, vars, params, memo),
                ),
                Node::Mul(x, y) => Node::Mul(
                    visit(g, x, out, vars, params, memo),
                    visit(g, y, out, vars, params, memo),
                ),
                Node::Neg(x) => Node::Neg(visit(g, x, out, vars, params, memo)),
            };
            let j = out.node(n);
            memo.insert(i, j);
            j
        }
        let mut out = Graph::default();
        let mut vars = vec![];
        let mut params = vec![];
        let root = visit(
            self,
            root,
            &mut out,
            &mut vars,
            &mut params,
            &mut HashMap::new(),
        );
        assert_eq!(root, out.nodes.len() - 1);
        (out.nodes, vars, params)
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Equation {
    pub(crate) template: usize,
    pub(crate) inputs: Vec<usize>,
    pub(crate) parameters: Vec<u64>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum Coverage {
    Boolean(usize),
    Equation(usize),
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Compiler {
    pub(crate) templates: Vec<Vec<Node>>,
    pub(crate) equations: Vec<Equation>,
    pub(crate) booleans: Vec<bool>,
    pub digest: [u8; 32],
    pub max_support: usize,
    coverage: Vec<Coverage>,
}
impl Compiler {
    pub const DIGEST: [u8; 32] = [
        144, 110, 86, 130, 183, 2, 82, 143, 185, 171, 134, 248, 183, 111, 27, 254, 57, 145, 163, 8,
        88, 63, 34, 21, 3, 74, 183, 218, 3, 84, 228, 220,
    ];
    /// Loads and authenticates the shared frozen compiler artifact.
    pub fn shared() -> Arc<Self> {
        static C: OnceLock<Arc<Compiler>> = OnceLock::new();
        C.get_or_init(|| {
            let c = postcard::from_bytes::<Self>(include_bytes!("sha_frozen/compiler.bin"))
                .expect("frozen official SHA compiler");
            let mut encoding = b"VMPCKKS/official-sha-narrow-compiler/1\0".to_vec();
            encoding.extend(
                postcard::to_allocvec(&(&c.templates, &c.equations, &c.booleans, &c.coverage))
                    .unwrap(),
            );
            assert_eq!(crate::arithmetic::hash(&encoding), Self::DIGEST);
            assert_eq!(c.digest, Self::DIGEST);
            Arc::new(c)
        })
        .clone()
    }
    #[cfg(test)]
    /// Reconstructs the compiler from all official SHA constraints.
    fn compile() -> Self {
        let a = Sha256Air;
        let constraints = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
        assert_eq!(constraints.len(), 8096);
        let mut g = Graph::default();
        let roots: Vec<_> = constraints.iter().map(|e| g.capture(e)).collect();
        let mut templates = vec![];
        let mut ids = HashMap::new();
        let mut equations = vec![];
        let mut booleans = vec![false; NUM_SHA256_COLS];
        let mut max_support = 0;
        let mut coverage = vec![];
        let bool_template = vec![
            Node::Input(0),
            Node::Constant(1),
            Node::Sub(0, 1),
            Node::Mul(0, 2),
        ];
        for root in roots {
            let (nodes, inputs, parameters) = g.normalize(root);
            max_support = max_support.max(inputs.len());
            if nodes == bool_template {
                assert_eq!(inputs.len(), 1);
                assert!(!booleans[inputs[0]]);
                booleans[inputs[0]] = true;
                coverage.push(Coverage::Boolean(inputs[0]));
                continue;
            }
            let template = *ids.entry(nodes.clone()).or_insert_with(|| {
                templates.push(nodes);
                templates.len() - 1
            });
            coverage.push(Coverage::Equation(equations.len()));
            equations.push(Equation {
                template,
                inputs,
                parameters,
            });
        }
        assert_eq!(booleans.iter().filter(|&&b| b).count(), 6656);
        assert_eq!(equations.len(), 1440);
        let mut encoding = b"VMPCKKS/official-sha-narrow-compiler/1\0".to_vec();
        encoding.extend(
            postcard::to_allocvec(&(&templates, &equations, &booleans, &coverage)).unwrap(),
        );
        let digest = crate::arithmetic::hash(&encoding);
        assert_eq!(
            digest,
            Self::DIGEST,
            "official SHA compiler artifact changed; update its version and authenticated digest"
        );
        Self {
            templates,
            equations,
            booleans,
            digest,
            max_support,
            coverage,
        }
    }
    #[cfg(test)]
    /// Generates the fixed official SHA polynomial evaluator source.
    pub fn evaluator_source(&self) -> String {
        use std::fmt::Write;
        let mut out = String::from(
            "use crate::arithmetic::F;\nuse p3_field::{Algebra, PrimeCharacteristicRing};\n#[inline(never)]\n/// Evaluates a fixed official SHA-256 polynomial template.\npub(crate) fn evaluate<E: Algebra<F> + Clone>(template: usize, m: &[E], p: &[E]) -> E {\n    match template {\n",
        );
        for (t, nodes) in self.templates.iter().enumerate() {
            writeln!(out, "        {t} => {{").unwrap();

            if t == 10 || t == 16 {
                out.push_str("            let mut acc = E::ZERO;\n");
                for i in 0..16 {
                    let a = 3 * i + 1;
                    let b = a + 1;
                    let c = a + 2;
                    if t == 10 {
                        writeln!(out,"            let bit = m[{c}].clone() + m[{a}].clone() * (m[{b}].clone() - m[{c}].clone());").unwrap();
                    } else {
                        writeln!(out,"            let ab = m[{a}].clone() * m[{b}].clone();\n            let bit = ab.clone() + m[{c}].clone() * (m[{a}].clone() + m[{b}].clone() - ab.mul_2exp_u64(1));").unwrap();
                    }
                    out.push_str("            acc = acc.mul_2exp_u64(1) + bit;\n");
                }
                out.push_str("            m[0].clone() - acc\n        },\n");
                continue;
            }
            for (i, node) in nodes.iter().enumerate() {
                let value = match node {
                    Node::Input(j) => format!("m[{j}].clone()"),
                    Node::Parameter(j) => format!("p[{j}].clone()"),
                    Node::Constant(c) => format!("E::from(F::from_u64({c}))"),
                    Node::Add(a, b) if a == b => format!("v{a}.mul_2exp_u64(1)"),
                    Node::Add(a, b) => format!("v{a}.clone() + v{b}.clone()"),
                    Node::Sub(a, b) => format!("v{a}.clone() - v{b}.clone()"),
                    Node::Mul(a, b) => format!("v{a}.clone() * v{b}.clone()"),
                    Node::Neg(a) => format!("-v{a}.clone()"),
                };
                writeln!(out, "            let v{i} = {value};").unwrap();
            }
            writeln!(out, "            v{}\n        }},", nodes.len() - 1).unwrap();
        }
        out.push_str("        _ => panic!(\"unknown official SHA template\"),\n    }\n}\n");
        out
    }
    #[cfg(test)]
    /// Rebuilds and serializes the frozen artifact for equivalence checks.
    pub fn frozen_bytes() -> Vec<u8> {
        postcard::to_allocvec(&Self::compile()).unwrap()
    }
    /// Returns the compiler and trace geometry statistics.
    pub fn report(&self) -> serde_json::Value {
        let mut hist = std::collections::BTreeMap::<usize, usize>::new();
        for e in &self.equations {
            *hist.entry(e.inputs.len()).or_default() += 1;
        }
        serde_json::json!({"version":1,"coverage_entries":self.coverage.len(),"original_columns":NUM_SHA256_COLS,"constraints":8096,"boolean_constraints":6656,"nonboolean_constraints":self.equations.len(),"templates":self.templates.len(),"max_parameters":self.equations.iter().map(|e|e.parameters.len()).max(),"template_nodes":self.templates.iter().map(Vec::len).sum::<usize>(),"max_support":self.max_support,"support_histogram":hist,"compiler_digest":self.digest})
    }
}

#[cfg(test)]
/// Evaluates the independent official SHA expression DAG.
fn evaluate<E: Algebra<F> + Clone>(
    nodes: &[Node],
    inputs: &[E],
    parameters: &[E],
    work: &mut Vec<E>,
) -> E {
    work.clear();
    for node in nodes {
        let v = match *node {
            Node::Input(i) => inputs[i].clone(),
            Node::Parameter(i) => parameters[i].clone(),
            Node::Constant(c) => E::from(F::from_u64(c)),
            Node::Add(x, y) => work[x].clone() + work[y].clone(),
            Node::Sub(x, y) => work[x].clone() - work[y].clone(),
            Node::Mul(x, y) => work[x].clone() * work[y].clone(),
            Node::Neg(x) => -work[x].clone(),
        };
        work.push(v);
    }
    work.last().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    #[test]
    /// Checks fixed SHA evaluation against the official DAG on arbitrary field inputs.
    fn fixed_evaluator_matches_original_dag_on_arbitrary_field_values() {
        let c = Compiler::shared();
        let mut rng = rand::rngs::StdRng::seed_from_u64(44112026);
        for _ in 0..64 {
            let m: Vec<F> = (0..72).map(|_| rng.random()).collect();
            let p: Vec<F> = (0..2).map(|_| rng.random()).collect();
            for (i, nodes) in c.templates.iter().enumerate() {
                assert_eq!(
                    evaluate(nodes, &m, &p, &mut vec![]),
                    crate::generated_sha::evaluate(i, &m, &p)
                );
            }
        }
    }
    #[test]
    /// Reconstructs every original official SHA constraint from the frozen compiler.
    fn compiler_reconstructs_every_original_constraint_exactly() {
        let c = Compiler::shared();
        assert_eq!(c.templates.len(), 21);
        assert_eq!(c.coverage.len(), 8096);
        assert_eq!(c.max_support, 68);
        let a = Sha256Air;
        let raw = get_symbolic_constraints::<F, _>(&a, AirLayout::from_air::<F>(&a));
        let mut graph = Graph::default();
        let roots: Vec<_> = raw.iter().map(|e| graph.capture(e)).collect();
        for (root, coverage) in roots.iter().zip(&c.coverage) {
            let reconstructed = match *coverage {
                Coverage::Boolean(column) => {
                    let x = graph.node(Node::Input(column));
                    let one = graph.node(Node::Constant(1));
                    let sub = graph.node(Node::Sub(x, one));
                    graph.node(Node::Mul(x, sub))
                }
                Coverage::Equation(index) => {
                    let e = &c.equations[index];
                    let mut nodes = vec![];
                    for n in &c.templates[e.template] {
                        let node = match *n {
                            Node::Input(i) => Node::Input(e.inputs[i]),
                            Node::Parameter(i) => Node::Constant(e.parameters[i]),
                            Node::Constant(v) => Node::Constant(v),
                            Node::Add(x, y) => Node::Add(nodes[x], nodes[y]),
                            Node::Sub(x, y) => Node::Sub(nodes[x], nodes[y]),
                            Node::Mul(x, y) => Node::Mul(nodes[x], nodes[y]),
                            Node::Neg(x) => Node::Neg(nodes[x]),
                        };
                        nodes.push(graph.node(node));
                    }
                    *nodes.last().unwrap()
                }
            };
            assert_eq!(
                *root, reconstructed,
                "official constraint was changed or omitted"
            );
        }
        let mut rng = StdRng::seed_from_u64(14101);
        for _ in 0..3 {
            let values: Vec<_> = (0..NUM_SHA256_COLS)
                .map(|_| F::from_u64(rng.random()))
                .collect();
            let mut raw_values: Vec<F> = vec![];
            for node in &graph.nodes {
                let v = match *node {
                    Node::Input(i) => values[i],
                    Node::Constant(x) => F::from_u64(x),
                    Node::Add(x, y) => raw_values[x] + raw_values[y],
                    Node::Sub(x, y) => raw_values[x] - raw_values[y],
                    Node::Mul(x, y) => raw_values[x] * raw_values[y],
                    Node::Neg(x) => -raw_values[x],
                    Node::Parameter(_) => unreachable!(),
                };
                raw_values.push(v);
            }
            let mut work = vec![];
            for (root, coverage) in roots.iter().zip(&c.coverage) {
                let value = match *coverage {
                    Coverage::Boolean(i) => values[i] * (values[i] - F::ONE),
                    Coverage::Equation(i) => {
                        let e = &c.equations[i];
                        let inputs: Vec<_> = e.inputs.iter().map(|&i| values[i]).collect();
                        let params: Vec<_> = e.parameters.iter().map(|&x| F::from_u64(x)).collect();
                        evaluate(&c.templates[e.template], &inputs, &params, &mut work)
                    }
                };
                assert_eq!(value, raw_values[*root]);
            }
        }
    }
}
