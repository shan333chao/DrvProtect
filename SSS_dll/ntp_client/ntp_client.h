
typedef 	  	struct _ControlWord
{
	unsigned int uLI : 2;       // 00 = no leap, clock ok   
	unsigned int uVersion : 3;  // version 3 or version 4
	unsigned int uMode : 3;     // 3 for client, 4 for server, etc.
	unsigned int uStratum : 8;  // 0 is unspecified, 1 for primary reference system,
								// 2 for next level, etc.
	int nPoll : 8;              // seconds as the nearest power of 2
	int nPrecision : 8;         // seconds to the nearest power of 2
}ControlWord;

typedef struct _NTPPacket
{
	union
	{
		ControlWord controlWord;

		int nControlWord;             // 4
	};

	int nRootDelay;                   // 4
	int nRootDispersion;              // 4
	int nReferenceIdentifier;         // 4

	__int64 n64ReferenceTimestamp;    // 8
	__int64 n64OriginateTimestamp;    // 8
	__int64 n64ReceiveTimestamp;      // 8

	int nTransmitTimestampSeconds;    // 4
	int nTransmitTimestampFractions;  // 4
}NTPPacket;



void  Get_time_t(time_t* time);
LONGLONG  get_time();
