// iverilog -t blif -o blinker.blif blinker.v
module blinker(
	input clock,
	input [1:0] sel,
	output reg[0:2] led);

reg [33:0] div;
reg [0:2] shift;

always @(posedge clock) begin
	div <= div + 1;
end

always @(posedge div[20]) begin
	shift[0:2] <= {~shift[2], shift[0:1]};
end

always @(posedge clock) begin
	case(sel)
	2'b00: led <= shift;
	2'b01: led <= ~shift;
	2'b10: led <= 3'b000;
	2'b11: led <= 3'b111;
	endcase
end

endmodule
