


/*!

	@file accesspoint_list.h
	@brief Header file for the access point list implementation.

*/



#include <stdio.h>
#include <string.h>
#include <stdlib.h>



/*!

	@brief Node in the accesspoint_list structure.

*/
struct accesspoint {

	struct accesspoint *next; ///< Next node in the list

	char ap_mac[6]; ///< 6-byte raw MAC address of access point
	int channel; ///< Channel at which this access point was most likely to occur
	char *ssid; ///< Advertised SSID
	char *location; ///< Advertised location
	int n_beacons_captured; ///< Number of beacons captured (may predict the actual channel)

};

/*!

	@brief List of accesspoint nodes

	Simply singly linked list for recording access point information during
	probes (done in the gather_aps functions in the attack method implementations).

	@see attack.h (gather_aps is documented here)

*/
struct accesspoint_list {

	/// Number of nodes in the list
	int n_accesspoints;

	/// List head
	struct accesspoint *head;
	/// List tail
	struct accesspoint *tail;

};

/*!

	@brief Callback function type for accesspoint_list_foreach.

	The function pointer passed to accesspoint_list_foreach will
	be casted to this type when the cb_data argument passed to the
	function is non-null.

*/
typedef int (*accesspoint_callback)(struct accesspoint*, void*);

/*!

	@brief Callback function type for accesspoint_list_foreach
	without a pointer to callback data.

	The function pointer passed to accesspoint_list_foreach will
	be casted to this type when the cb_data argument passed to the
	function is NULL. This removes the need to add a callback data
	argument in the callback functions where it is unnecessary.

*/
typedef int (*accesspoint_callback_nocbdata)(struct accesspoint*);



struct accesspoint *accesspoint_alloc(void);
struct accesspoint_list *accesspoint_list_new(void);
void accesspoint_list_push_front(struct accesspoint_list *list, struct accesspoint *accesspoint); // At head
void accesspoint_list_push_back(struct accesspoint_list *list, struct accesspoint *accesspoint); // At tail
void accesspoint_list_push(struct accesspoint_list *list, struct accesspoint *accesspoint); // At head
void accesspoint_list_insert(struct accesspoint_list *list, struct accesspoint *accesspoint); // At tail
struct accesspoint *accesspoint_list_front(struct accesspoint_list *list); // Head
struct accesspoint *accesspoint_list_back(struct accesspoint_list *list); // Tail
struct accesspoint *accesspoint_list_top(struct accesspoint_list *list); // Head
int accesspoint_list_pop_front(struct accesspoint_list *list); // Head
int accesspoint_list_pop(struct accesspoint_list *list); // Head
int accesspoint_list_foreach(struct accesspoint_list *list, void *accesspoint_cb, void *cb_data);
void accesspoint_list_empty(struct accesspoint_list *list);
void accesspoint_list_free(struct accesspoint_list *list);
void accesspoint_list_print(struct accesspoint_list *list);
struct accesspoint_list *accesspoint_list_load(const char *file_name);
void accesspoint_list_test(char *file_name);



