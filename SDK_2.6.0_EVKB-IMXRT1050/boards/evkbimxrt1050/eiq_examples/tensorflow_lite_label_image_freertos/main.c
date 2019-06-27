/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"

/* Freescale includes. */
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Task priorities. */
#define inference_task_PRIORITY (configMAX_PRIORITIES - 1)
#define INFERENCE_TASK_STACK_SIZE (1024 * 32)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static void inference_task(void *pvParameters);
extern void do_inference(void);

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Application entry point.
 */
int main(void)
{
    /* Init board hardware. */
    BOARD_ConfigMPU();
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    if (xTaskCreate(inference_task, "Inference_task", INFERENCE_TASK_STACK_SIZE, NULL, inference_task_PRIORITY, NULL) != pdPASS)
    {
        PRINTF("Task creation failed!.\r\n");
        while (1)
            ;
    }

    vTaskStartScheduler();

    for (;;)
        ;
}

static void inference_task(void *pvParameters)
{
    for (;;)
    {
        do_inference();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

