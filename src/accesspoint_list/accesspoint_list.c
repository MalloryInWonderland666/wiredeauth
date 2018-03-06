


/*!

	@file accesspoint_list.c

	@brief Singly linked list data structure for access point information.

	Simple linked list implementation with stack/queue insertion/removal
	functions for recording access point information during probes (done
	in the gather_aps functions in the attack method implementations).

	@see attack.h (gather_aps is documented here)

	Callback implementations are provided to facilitate unduplicated
	insertion. Unduplicated insertion will be in O(n) but is favored
	over memory inefficiency.

	FIXME:
		- Fix faulty file reading implementation

*/



#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "accesspoint_list.h"
#include "wiredeauth_debug.h"



/// Maximum line size to assume when loading access point records from a file
#define MAX_LINESZ 1024



////////////////////////////////////////////////////////
///////////////////// USER-DEFINED /////////////////////
////////////////////////////////////////////////////////

/*!

	@brief Allocate memory an accesspoint list node and initialize
	with defaults.

	@return Pointer to created accesspoint node, or NULL on failure.

*/
struct accesspoint *accesspoint_alloc(void) {

	struct accesspoint *accesspoint =
		(struct accesspoint*)malloc(sizeof(struct accesspoint));

	if ( !accesspoint ) {
		PRINTF("accesspoint_alloc: Memory allocation failure.\n");
		return NULL;
	}

	// Initialization code here
	memset(&(accesspoint->ap_mac), 0, 6);
	accesspoint->channel = 0; // Undecided
	accesspoint->ssid = NULL;
	accesspoint->location = NULL;
	accesspoint->n_beacons_captured = 0;

	return accesspoint;

}

/*!

	@brief Allocate memory an accesspoint list and initialize from
	a file of accesspoint records.

	Each line in the record file must contain the following string
	(in the same order) separated by the pipe character '|':
		- 2-digit formatted MAC address seperated by full colons
		(case insensitive)
		- Advertised access point SSID
		- Advertised access point location
		- Probing channel when this access point was discovered
		- Number of captured beacon frames for this access point
	Unknown or inapplicable fields should be left with an underscore.
	For example:
		- 06:32:D0:7F:0F:E4|Wireless|_|11|46
	In case the same access point is detected on multiple contiguous
	channels, the beacon capture count will be used to predict the
	actual channel.

	@param file_name C string containing absolute or relative path
	to record file.

	@return Pointer to created accesspoint node, or NULL on failure.

*/
struct accesspoint_list *accesspoint_list_load(const char *file_name) {

	FILE *fd;
	char line[MAX_LINESZ];
	struct accesspoint_list *list;

	// Load from file here

	fd = fopen(file_name, "rb");
	if (fd == NULL) {
		PRINTF("Failed to open file \"%s\"\n", file_name);
		return NULL;
	}

	list = accesspoint_list_new();

	while (fgets(line, MAX_LINESZ, fd)) {

		struct accesspoint *accesspoint;

		accesspoint = accesspoint_alloc();
/*
		sscanf(

			// FIXME: this line won't work
			line, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x|%s|%s|%d|%d",

			&(accesspoint->ap_mac[0]), &(accesspoint->ap_mac[1]),
			&(accesspoint->ap_mac[2]), &(accesspoint->ap_mac[3]),
			&(accesspoint->ap_mac[4]), &(accesspoint->ap_mac[5]),

			&(accesspoint->ssid), &(accesspoint->location),
			&(accesspoint->channel), &(accesspoint->n_beacons_captured)

		);
*/
		accesspoint_list_insert(list, accesspoint);

	}

	fclose(fd);

	return list;

}

/*!

	@brief Free memory allocated for an accesspoint list node.

	Meant to be passed to accesspoint_list_foreach as a callback
	function in accesspoint_list_free and accesspoint_list_empty.

	@see accesspoint_list_foreach
	@see accesspoint_list_free
	@see accesspoint_list_empty

	Pointer members are assumed to point to allocated regions if
	not NULL, so avoid making modifications to these fields that
	can cause problems for deallocation.

	@param accesspoint Pointer to the accesspoint node in the list.

	@return 0 on success, or -1 on failure.

*/
static int free_accesspoint(struct accesspoint *accesspoint) {

	// Delete necessary things here
	if (accesspoint->ssid)
		free(accesspoint->ssid);
	if (accesspoint->location)
		free(accesspoint->location);

	free(accesspoint);

	return 0;

}

/*!

	@brief Print an accesspoint node in the list.

	Meant to be passed to accesspoint_list_foreach as a callback
	function in accesspoint_list_print.

	@see accesspoint_list_foreach
	@see accesspoint_list_print

	@param accesspoint Pointer to the accesspoint node in the list.

	@return Just 0

*/
static int print_accesspoint(struct accesspoint *accesspoint) {

	// Printing code here

	PRINTF("Access point:\n");

	PRINTF(
		"\tMAC = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		accesspoint->ap_mac[0], accesspoint->ap_mac[1],
		accesspoint->ap_mac[2], accesspoint->ap_mac[3],
		accesspoint->ap_mac[4], accesspoint->ap_mac[5]
	);

	if (accesspoint->channel)
		PRINTF("\tChannel = %d\n", accesspoint->channel);

	if (accesspoint->ssid)
		PRINTF("\tSSID = %s\n", accesspoint->ssid);

	if (accesspoint->location)
		PRINTF("\tAdvertised location = %s\n", accesspoint->location);

	PRINTF("\tCaptured beacon frames = %d\n", accesspoint->n_beacons_captured);

	return 0;

}



///////////////////////////////////////////////////////
////////////////////// AUTOMATIC //////////////////////
///////////////////////////////////////////////////////

/*!

	@brief Allocate memory for an accesspoint_list and initialize
	with defaults.

	@return Pointer to the created list, or NULL on failure

*/
struct accesspoint_list *accesspoint_list_new(void) {

	struct accesspoint_list *list =
		(struct accesspoint_list*)malloc(sizeof(struct accesspoint_list));

	if ( list == NULL ) {
		PRINTF("accesspoint_list_new: Allocation failure.\n");
		return NULL;
	}

	list->n_accesspoints = 0;

	list->head = NULL;
	list->tail = NULL;

	return list;

}

/*!

	@brief Insert an accesspoint struct pointer at the head
	of the list.

	@param list Pointer to an accesspoint_list struct
	@param accesspoint accesspoint struct pointer to insert

*/
void accesspoint_list_push_front(struct accesspoint_list *list, struct accesspoint *accesspoint) {

	if (list->n_accesspoints == 0) {

		accesspoint->next = NULL;
		list->head = list->tail = accesspoint;

	} else {

		accesspoint->next = list->head;
		list->head = accesspoint;

	}

	list->n_accesspoints += 1;

	return;

}

/*!

	@brief Insert an accesspoint struct pointer at the tail
	of the list.

	@param list Pointer to an accesspoint_list struct
	@param accesspoint accesspoint struct pointer to insert

*/
void accesspoint_list_push_back(struct accesspoint_list *list, struct accesspoint *accesspoint) {

	if (list->n_accesspoints == 0) {

		accesspoint->next = NULL;
		list->head = list->tail = accesspoint;

	} else {

		accesspoint->next = NULL;
		list->tail->next = accesspoint;
		list->tail = accesspoint;

	}

	list->n_accesspoints += 1;

	return;

}

/*!

	@brief Insert an accesspoint struct pointer at the head
	of the list.

	@param list Pointer to an accesspoint_list struct
	@param accesspoint accesspoint struct pointer to insert

*/
void accesspoint_list_push(struct accesspoint_list *list, struct accesspoint *accesspoint) {

	accesspoint_list_push_front(list, accesspoint);

	return;

}

/*!

	@brief Insert an accesspoint struct pointer at the tail
	of the list.

	@param list Pointer to an accesspoint_list struct
	@param accesspoint accesspoint struct pointer to insert

*/
void accesspoint_list_insert(struct accesspoint_list *list, struct accesspoint *accesspoint) {

	accesspoint_list_push_back(list, accesspoint);

	return;

}

/*!

	@brief Retrieve a pointer to the head of the list.

	@param list Pointer to an accesspoint_list struct

	@return Pointer to the head of the list

*/
struct accesspoint *accesspoint_list_front(struct accesspoint_list *list) {

	return list->head;

}

/*!

	@brief Retrieve a pointer to the tail of the list.

	@param list Pointer to an accesspoint_list struct

	@return Pointer to the tail of the list

*/
struct accesspoint *accesspoint_list_back(struct accesspoint_list *list) {

	return list->tail;

}

/*!

	@brief Retrieve a pointer to the head of the list.

	@param list Pointer to an accesspoint_list struct

	@return Pointer to the head of the list

*/
struct accesspoint *accesspoint_list_top(struct accesspoint_list *list) {

	return list->head;

}

/*!

	@brief Remove the head of the list.

	@param list Pointer to an accesspoint_list struct

	@return 0 on success, -1 if there was nothing to remove

*/
int accesspoint_list_pop_front(struct accesspoint_list *list) {

	struct accesspoint *next;

	if (list->n_accesspoints == 0)
		return -1;

	if (list->n_accesspoints == 1) {

		free_accesspoint(list->head);
		list->head = list->tail = NULL;
		list->n_accesspoints = 0;

		return 0;

	}

	next = list->head->next;
	free_accesspoint(list->head);
	list->head = next;
	list->n_accesspoints -= 1;

	return 0;

}

/*!

	@brief Remove the head of the list.

	@param list Pointer to an accesspoint_list struct

	@return 0 on success, -1 if there was nothing to remove

*/
int accesspoint_list_pop(struct accesspoint_list *list) {

	return accesspoint_list_pop_front(list);

}

/*!

	@brief Invoke a callback function on all accesspoint pointers
	in the list.

	The callback function must take a pointer to an accesspoint
	struct, optionally a pointer to callback data, and return an
	integer result. The return value of this function will be the
	sum of results returned by each invocation of the callback
	function. This is intended to be useful where the callback
	would be an indicator function, and we want the number of
	successes after iterating over all list nodes.

	accesspoint_cb is taken as a void pointer to a function and
	the actual function type is decided at runtime as either a
	function taking an accesspoint struct pointer or a function
	taking both an accesspoint struct pointer and callback data.
	If cb_data is NULL then accesspoint_cb is assumed to be of
	the former type, otherwise it is assumed to be of the latter
	type and cb_data will be passed to the function as a second
	argument.

	@param list Pointer to an accesspoint_list struct
	@param accesspoint_cb Function pointer to callback function
	@param cb_data Pointer to callback data

	@see accesspoint_callback
	@see accesspoint_callback_nocbdata

	@return Integer sum of invocation results

*/
int accesspoint_list_foreach(struct accesspoint_list *list, void *accesspoint_cb, void *cb_data) {

	int sum = 0;

	struct accesspoint *iter = list->head;

	if ( cb_data )

		while (iter) {
			struct accesspoint *next = iter->next;
			sum += ((accesspoint_callback)accesspoint_cb)(iter, cb_data);
			iter = next;
		}

	else

		while (iter) {
			struct accesspoint *next = iter->next;
			sum += ((accesspoint_callback_nocbdata)accesspoint_cb)(iter);
			iter = next;
		}

	return sum;

}

/*!

	@brief Destroy all nodes and empty the list.

	@param list Pointer to an accesspoint_list struct

*/
void accesspoint_list_empty(struct accesspoint_list *list) {

	accesspoint_list_foreach(list, free_accesspoint, NULL);

	list->n_accesspoints = 0;

	list->head = NULL;
	list->tail = NULL;

	return;

}

/*!

	@brief Destroy all nodes along with the list.

	@param list Pointer to an accesspoint_list struct

*/
void accesspoint_list_free(struct accesspoint_list *list) {

	accesspoint_list_foreach(list, free_accesspoint, NULL);

	free(list);

	return;

}

/*!

	@brief Print all nodes in the list.

	Printing will be done as specified in print_accesspoint.

	@see print_accesspoint

	@param list Pointer to an accesspoint_list struct

*/
void accesspoint_list_print(struct accesspoint_list *list) {

	accesspoint_list_foreach(list, print_accesspoint, NULL);

	return;

}

/*!

	@brief Test implementations.

	Loads a list from a file, displays it and destroys the list.

	@param file_name Relative or absolute path to the record file.

*/
void accesspoint_list_test(char *file_name) {

	struct accesspoint_list *list = accesspoint_list_load(file_name);

	accesspoint_list_print(list);

	accesspoint_list_free(list);

	return;

}




