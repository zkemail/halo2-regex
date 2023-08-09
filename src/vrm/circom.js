function genCircomAllstr(graph_json, template_name) {
    const N = graph_json.length;
    const graph = Array(N).fill({});
    const rev_graph = Array(N).fill({});
    let accept_nodes = new Set();
    for (let i = 0; i < N; i++) {
        for (let k in graph_json[i]["edges"]) {
            const v = graph_json[i]["edges"][k];
            graph[i][k] = v;
            rev_graph[v][i] = k;
        }
        if (graph_json[i]["type"] == "accept") {
            accept_nodes.add(i);
        }
    }
    if (accept_nodes[0] != null) {
        throw new Error("accept node must not be 0");
    }
    accept_nodes = [...accept_nodes];
    if (accept_nodes.length != 1) {
        throw new Error("the size of accept nodes must be one");
    }

    let eq_i = 0;
    let lt_i = 0;
    let and_i = 0;
    let multi_or_i = 0;

    let lines = [];
    lines.push("\tfor (var i = 0; i < num_bytes; i++) {");

    const uppercase = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    const lowercase = new Set("abcdefghijklmnopqrstuvwxyz");
    const digits = new Set("0123456789");
    for (let i = 1; i < N; i++) {
        const outputs = [];
        for (let prev_i in Object.keys(rev_graph[i])) {
            const k = rev_graph[i][prev_i];
            // const prev_i = elem[1];
            const eq_outputs = [];
            const vals = new Set(k);
            // if (vals.has("^")) {
            //     vals.delete("^");
            //     lines.push("\t\ti==0;");
            // }
            if (vals.isSuperset(uppercase)) {
                vals.difference(uppercase);
                lines.push(`\t\tlt[${lt_i}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i}][i].in[0] <== 64;`);
                lines.push(`\t\tlt[${lt_i}][i].in[1] <== in[i];`);

                lines.push(`\t\tlt[${lt_i + 1}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[0] <== in[i];`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[1] <== 91;`);

                lines.push(`\t\tand[${and_i}][i] = AND();`);
                lines.push(`\t\tand[${and_i}][i].a <== lt[${lt_i}][i].out;`);
                lines.push(`\t\tand[${and_i}][i].b <== lt[${lt_i + 1}][i].out;`);

                eq_outputs.push(['and', and_i]);
                lt_i += 2
                and_i += 1
            }
            if (vals.isSuperset(lowercase)) {
                vals.difference(lowercase);
                lines.push(`\t\tlt[${lt_i}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i}][i].in[0] <== 96;`);
                lines.push(`\t\tlt[${lt_i}][i].in[1] <== in[i];`);

                lines.push(`\t\tlt[${lt_i + 1}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[0] <== in[i];`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[1] <== 123;`);

                lines.push(`\t\tand[${and_i}][i] = AND();`);
                lines.push(`\t\tand[${and_i}][i].a <== lt[${lt_i}][i].out;`);
                lines.push(`\t\tand[${and_i}][i].b <== lt[${lt_i + 1}][i].out;`);

                eq_outputs.push(['and', and_i]);
                lt_i += 2
                and_i += 1
            }
            if (vals.isSuperset(digits)) {
                vals.difference(digits);
                lines.push(`\t\tlt[${lt_i}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i}][i].in[0] <== 47;`);
                lines.push(`\t\tlt[${lt_i}][i].in[1] <== in[i];`);

                lines.push(`\t\tlt[${lt_i + 1}][i] = LessThan(8);`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[0] <== in[i];`);
                lines.push(`\t\tlt[${lt_i + 1}][i].in[1] <== 58;`);

                lines.push(`\t\tand[${and_i}][i] = AND();`);
                lines.push(`\t\tand[${and_i}][i].a <== lt[${lt_i}][i].out;`);
                lines.push(`\t\tand[${and_i}][i].b <== lt[${lt_i + 1}][i].out;`);

                eq_outputs.push(['and', and_i]);
                lt_i += 2
                and_i += 1
            }
            for (let c of vals) {
                if (c.length != 1) {
                    throw new Error("c.length must be 1");
                }
                lines.push(`\t\teq[${eq_i}][i] = IsEqual();`);
                lines.push(`\t\teq[${eq_i}][i].in[0] <== in[i];`);
                lines.push(`\t\teq[${eq_i}][i].in[1] <== ${c.charCodeAt()};`);
                eq_outputs.push(['eq', eq_i]);
                eq_i += 1
            }

            lines.push(`\t\tand[${and_i}][i] = AND();`);
            lines.push(`\t\tand[${and_i}][i].a <== states[i][${prev_i}];`);
            if (eq_outputs.length == 1) {
                lines.push(`\t\tand[${and_i}][i].b <== ${eq_outputs[0][0]}[${eq_outputs[0][1]}][i].out;`);
            } else if (eq_outputs.length > 1) {
                lines.push(`\t\tmulti_or[${multi_or_i}][i] = MultiOR(${eq_outputs.length});`);
                for (let output_i = 0; output_i < eq_outputs.length; output_i++) {
                    lines.push(`\t\tmulti_or[${multi_or_i}][i].in[${output_i}] <== ${eq_outputs[output_i][0]}[${eq_outputs[output_i][1]}][i].out;`);
                }
                lines.push(`\t\tand[${and_i}][i].b <== multi_or[${multi_or_i}][i].out;`);
                multi_or_i += 1
            }

            outputs.push(and_i);
            and_i += 1;
        }

        if (outputs.length == 1) {
            lines.push(`\t\tstates[i+1][${i}] = and[${outputs[0]}][i].out;`);
        } else if (outputs.length > 1) {
            lines.push(`\t\tmulti_or[${multi_or_i}][i] = MultiOR(${outputs.length});`);
            for (let output_i = 0; output_i < outputs.length; output_i++) {
                lines.push(`\t\tmulti_or[${multi_or_i}][i].in[${output_i}] <== and[${outputs[output_i]}][i].out;`);
            }
            lines.push(`\t\tstates[i+1][${i}] = multi_or[${multi_or_i}][i].out;`);
            multi_or_i += 1
        }
        // uppercase = set(string.ascii_uppercase)
        // lowercase = set(string.ascii_lowercase)
        // digits = set(string.digits)
        // vals = set(vals)
    }
    lines.push("\t}");

    const declarations = [];
    declarations.push(`pragma circom 2.1.5;\ninclude "@zk-email/circuits/regexes/regex_helpers.circom";\n`);
    declarations.push(`template ${template_name}(msg_bytes) {`);
    declarations.push(`\tsignal input msg[msg_bytes];`);
    declarations.push(`\tsignal output out;\n`);
    declarations.push(`\tvar num_bytes = msg_bytes+1;`);
    declarations.push(`\tsignal in[num_bytes];`);
    declarations.push(`\tin[0]<==128;`);
    declarations.push(`\tfor (var i = 0; i < msg_bytes; i++) {`);
    declarations.push(`\t\tin[i+1] <== msg[i];`);
    declarations.push(`\t}\n`);
    if (eq_i > 0) {
        declarations.push(`\tcomponent eq[${eq_i}][num_bytes];`);
    }
    if (lt_i > 0) {
        declarations.push(`\tcomponent lt[${lt_i}][num_bytes];`);
    }
    if (and_i > 0) {
        declarations.push(`\tcomponent and[${and_i}][num_bytes];`);
    }
    if (multi_or_i > 0) {
        declarations.push(`\tcomponent multi_or[${multi_or_i}][num_bytes];`);
    }
    declarations.push(`\tsignal states[num_bytes+1][${N}];`);
    declarations.push("");

    const init_code = [];
    init_code.push("\tfor (var i = 0; i < num_bytes; i++) {");
    init_code.push(`\t\tstates[i][0] <== 1;`);
    init_code.push("\t}");
    init_code.push(`\tfor (var i = 1; i < ${N}; i++) {`);
    init_code.push(`\t\tstates[0][i] <== 0;`);
    init_code.push("\t}");
    init_code.push("");

    lines = declarations.concat(init_code).concat(lines);

    const accept_node = accept_nodes[0];
    const accept_lines = [""];
    accept_lines.push("\tsignal final_state_sum[num_bytes+1];");
    accept_lines.push(`\tfinal_state_sum[0] <== states[0][${accept_node}];`);
    accept_lines.push("\tfor (var i = 1; i <= num_bytes; i++) {");
    accept_lines.push(`\t\tfinal_state_sum[i] <== final_state_sum[i-1] + states[i][${accept_node}];`);
    accept_lines.push("\t}");
    accept_lines.push("\tout <== final_state_sum[num_bytes];");

    lines = lines.concat(accept_lines);
    let string = lines.reduce((res, line) => res + line + "\n", "");
    return string;
}



Set.prototype.isSuperset = function (subset) {
    if (this.size == 0) {
        return false;
    }
    for (var elem of subset) {
        if (!this.has(elem)) {
            return false;
        }
    }
    return true;
}

Set.prototype.difference = function (setB) {
    for (let elem of setB) {
        this.delete(elem)
    }
}
