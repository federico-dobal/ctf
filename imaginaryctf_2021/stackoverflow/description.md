The binary has two potential outcomes(for details see ida_view.png) identified by different messages:

* SUCCESS: "DEBUG MODE ACTIVATED"
* FAILURE: "ERROR: FRATURE NOT IMPLEMENTED YET"

The solution uses Angr tool(https://angr.io/) to search for inputs reaching SUCCESS state and avoiding FAILURE ones.
