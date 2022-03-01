import matplotlib as mpl
import matplotlib.pyplot as plt

mpl.use("GTK4Cairo")

# plt.rc("text", usetext=True)
# plt.rc("text.latex", preamble=r"\usepackage{amsmath}")

# coconut: 10 validators, 7 threshold, 1 private attribute, 0 public attributes
x_values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

request_issued = [123.81, 319.89, 475.30, 633.99, 792.22, 924.26, 1079.7, 1231.6, 1385.0, 1539.0]
request_issued_size = [3112, 6056, 9000, 11944, 14888, 17832, 20776, 23720, 26664, 29608]

issuance_issued = [122.62, 298.32, 440.54, 585.81, 730.40, 853.37, 993.84, 1052.70, 1279.2, 1417.8]
issuance_issued_size = [value * 96 for value in x_values]

unblind_issued = [27.183, 62.699, 93.764, 125.48, 152.69, 182.33, 212.89, 233.10, 274.36, 304.22]

request_spent = [168.21, 193.33, 210.71, 226.95, 237.80, 253.30, 271.17, 261.55, 275.35, 289.01]
request_spent_size = [3432, 3752, 4072, 4392, 4712, 5032, 5352, 5672, 5992, 6312]

issuance_spent = [173.41, 185.53, 203.88, 222.26, 235.34, 234.05, 270.08, 288.84, 307.07, 327.44]
issuance_spent_size = [96] * len(x_values)

unblind_spent = [27.081, 31.261, 31.330, 31.348, 30.496, 25.735, 30.416, 30.595, 30.503, 30.536]

request_equal = [183.24, 352.56, 526.95, 701.47, 852.48, 970.84, 1195.5, 1365.5, 1544.0, 1715.0]
request_equal_size = [3432, 6696, 9960, 13224, 16488, 19752, 23016, 26280, 29544, 32808]

issuance_equal = [168.90, 331.38, 495.33, 659.67, 800.14, 966.02, 1119.4, 1282.7, 1445.5, 1596.3]
issuance_equal_size = [value * 96 for value in x_values]

unblind_equal = [38.714, 62.619, 94.457, 125.17, 151.96, 183.68, 212.76, 242.69, 274.38, 304.13]

spend_user = [18.862, 34.509, 51.780, 68.478, 83.372, 100.15, 116.49, 133.05, 149.62, 166.42]
spend_size = [488, 808, 1128, 1448, 1768, 2088, 2408, 2728, 3048, 3368]
spend_verifier = [20.944, 39.551, 57.977, 76.481, 92.709, 111.45, 128.80, 146.49, 164.95, 182.33]

# plot
fig, ax1 = plt.subplots()

ax1.set_title("Request protocol, user-side", fontsize=16)
ax1.set_xlabel("Number of vouchers x", fontsize=14)
ax1.set_ylabel("Computational cost [ms]", fontsize=14)

ax1.plot(x_values, request_issued, label="Request x vouchers", marker="o", alpha=0.8)
ax1.plot(x_values, request_spent, label="Exchange x vouchers for 1 voucher", marker="o", alpha=0.8)
ax1.plot(x_values, request_equal, label="Exchange x vouchers for x vouchers", marker="o", alpha=0.8)

ax1.legend(loc="upper left", fontsize=12)

ax1.tick_params(axis="both", which="major", labelsize=12)
ax1.set_xticks(x_values)
ax1.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Request protocol, user-side", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax2 = plt.subplots()

ax2.set_title("Request protocol, from user to authority", fontsize=16)
ax2.set_xlabel("Number of vouchers x", fontsize=14)
ax2.set_ylabel("Communication cost [bytes]", fontsize=14)

ax2.plot(x_values, request_issued_size, label="Request x vouchers", marker="o", alpha=0.8)
ax2.plot(x_values, request_spent_size, label="Exchange x vouchers for 1 voucher", marker="o", alpha=0.8)
ax2.plot(x_values, request_equal_size, label="Exchange x vouchers for x vouchers", marker="o", alpha=0.8)

ax2.legend(loc="upper left", fontsize=12)

ax2.tick_params(axis="both", which="major", labelsize=12)
ax2.set_xticks(x_values)
ax2.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Request protocol, from user to authority", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax3 = plt.subplots()

ax3.set_title("Issuance protocol, authority-side", fontsize=16)
ax3.set_xlabel("Number of vouchers x", fontsize=14)
ax3.set_ylabel("Computational cost [ms]", fontsize=14)

ax3.plot(x_values, issuance_issued, label="Request x vouchers", marker="o", alpha=0.8)
ax3.plot(x_values, issuance_spent, label="Exchange x vouchers for 1 voucher", marker="o", alpha=0.8)
ax3.plot(x_values, issuance_equal, label="Exchange x vouchers for x vouchers", marker="o", alpha=0.8)

ax3.legend(loc="upper left", fontsize=12)

ax3.tick_params(axis="both", which="major", labelsize=12)
ax3.set_xticks(x_values)
ax3.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Issuance protocol, authority-side", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax4 = plt.subplots()

ax4.set_title("Issuance protocol, from authority to user", fontsize=16)
ax4.set_xlabel("Number of vouchers x", fontsize=14)
ax4.set_ylabel("Communication cost [bytes]", fontsize=14)

ax4.plot(x_values, issuance_issued_size, label="Request x vouchers", marker="o", alpha=0.8)
ax4.plot(x_values, issuance_spent_size, label="Exchange x vouchers for 1 voucher", marker="o", alpha=0.8)
ax4.plot(x_values, issuance_equal_size, label="Exchange x vouchers for x vouchers", marker="x", alpha=0.8)

ax4.legend(loc="upper left", fontsize=12)

ax4.tick_params(axis="both", which="major", labelsize=12)
ax4.set_xticks(x_values)
ax4.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Issuance protocol, from authority to user", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax5 = plt.subplots()

ax5.set_title("Issuance protocol, user-side", fontsize=16)
ax5.set_xlabel("Number of vouchers x", fontsize=14)
ax5.set_ylabel("Computational cost [ms]", fontsize=14)

ax5.plot(x_values, unblind_issued, label="Request x vouchers", marker="o", alpha=0.8)
ax5.plot(x_values, unblind_spent, label="Exchange x vouchers for 1 voucher", marker="o", alpha=0.8)
ax5.plot(x_values, unblind_equal, label="Exchange x vouchers for x vouchers", marker="x", alpha=0.8)

ax5.legend(loc="upper left", fontsize=12)

ax5.tick_params(axis="both", which="major", labelsize=12)
ax5.set_xticks(x_values)
ax5.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Issuance protocol, user-side", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax6 = plt.subplots()

ax6.set_title("Spend protocol, user-side", fontsize=16)
ax6.set_xlabel("Number of vouchers x", fontsize=14)
ax6.set_ylabel("Computational cost [ms]", fontsize=14)

ax6.plot(x_values, spend_user, label="Spend x vouchers", marker="o", alpha=0.8, color="red")

ax6.legend(loc="upper left", fontsize=12)

ax6.tick_params(axis="both", which="major", labelsize=12)
ax6.set_xticks(x_values)
ax6.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Spend protocol, user-side", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax6 = plt.subplots()

ax6.set_title("Spend protocol, from user to provider", fontsize=16)
ax6.set_xlabel("Number of vouchers x", fontsize=14)
ax6.set_ylabel("Communication cost [bytes]", fontsize=14)

ax6.plot(x_values, spend_size, label="Spend x vouchers", marker="o", alpha=0.8, color="red")

ax6.legend(loc="upper left", fontsize=12)

ax6.tick_params(axis="both", which="major", labelsize=12)
ax6.set_xticks(x_values)
ax6.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Spend protocol, from user to provider", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax6 = plt.subplots()

ax6.set_title("Spend protocol, provider-side", fontsize=16)
ax6.set_xlabel("Number of vouchers x", fontsize=14)
ax6.set_ylabel("Computational cost [ms]", fontsize=14)

ax6.plot(x_values, spend_verifier, label="Spend x vouchers", marker="o", alpha=0.8, color="red")

ax6.legend(loc="upper left", fontsize=12)

ax6.tick_params(axis="both", which="major", labelsize=12)
ax6.set_xticks(x_values)
ax6.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Spend protocol, provider-side", bbox_inches="tight", dpi=300)
# plt.show()
